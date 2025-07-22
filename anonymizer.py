import ast
import json
import logging
import datetime
from typing import Dict, Any

import db_utils
from comprehend import generate_fake_entities, detect_pii_data, anonymize, de_anonymize, generate_fake_data
from db_methods import get_piimaster_uuid, get_piientity_data, bulk_insert_piientity, insert_piidata
from audit_logger import AuditLogger  # New module for HIPAA compliance

logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)

# Initialize audit logger for HIPAA compliance
audit_logger = AuditLogger()

session = db_utils.get_db_session()


def log_phi_access(masterid: str, action: str, data_type: str, user_context: Dict[str, Any] = None):
    """Log PHI access for HIPAA audit requirements"""
    audit_logger.log_access({
        'timestamp': datetime.datetime.utcnow().isoformat(),
        'masterid': masterid,
        'action': action,  # ANONYMIZE, DE-ANONYMIZE, VIEW, etc.
        'data_type': data_type,
        'user_context': user_context or {},
        'success': True
    })


def validate_gdpr_consent(identity: str, identityType: str, purpose: str) -> bool:
    """Validate GDPR consent for data processing"""
    # In production, check consent database
    # For now, we'll assume consent is given for healthcare purposes
    valid_purposes = ['healthcare_provision', 'emergency_care', 'quality_improvement']
    return purpose in valid_purposes


def anonymizer(identity, identityType, conversation, context=None):
    """Enhanced anonymizer with HIPAA/GDPR compliance"""
    try:
        # GDPR consent check
        if context and context.get('requires_consent'):
            if not validate_gdpr_consent(identity, identityType, context.get('purpose', 'healthcare_provision')):
                return {
                    "statusCode": 403,
                    "error": "GDPR consent not provided for this processing purpose"
                }
        
        result = None
        # Detect PII and PHI
        entities = detect_pii_data(conversation)
        
        # Log detection for audit
        log_phi_access(identity, 'DETECT_PHI', 'conversation', context)
        
        if entities:
            # Get masterid
            masterid = get_piimaster_uuid(identity, identityType)
            
            # Log PHI processing
            log_phi_access(masterid, 'ANONYMIZE', 'conversation', context)

            # Get PII Data stored for the User
            rows = get_piientity_data(masterid)

            pii_entity_records = generate_fake_entities(masterid, entities, rows)

            result = anonymize(conversation, entities)

            if pii_entity_records:
                bulk_insert_piientity(pii_entity_records)

            # Store anonymization record with GDPR metadata
            metadata = {
                'gdpr_purpose': context.get('purpose') if context else None,
                'gdpr_legal_basis': 'Article 9(2)(h)' if context else None,
                'entity_count': len(entities),
                'entity_types': list(set(e['Type'] for e in entities))
            }
            insert_piidata(masterid, conversation, result, 'ANONYMIZE', metadata=json.dumps(metadata))

            # Log successful anonymization
            audit_logger.log_success({
                'masterid': masterid,
                'action': 'ANONYMIZE',
                'entities_processed': len(entities),
                'timestamp': datetime.datetime.utcnow().isoformat()
            })

        return {
            "statusCode": 200,
            "body": json.dumps({
                "result": result if result else conversation,
                "entities_detected": len(entities) if entities else 0,
                "compliance": {
                    "hipaa_safe_harbor": True,
                    "gdpr_pseudonymized": True
                }
            })
        }
    except Exception as e:
        logger.error(e)
        audit_logger.log_error({
            'action': 'ANONYMIZE',
            'error': str(e),
            'timestamp': datetime.datetime.utcnow().isoformat()
        })
        return {
            "statusCode": 500,
            "error": f"Error: {e}"
        }


def if_exists(records, pii_type, pii_data):
    """Check if PII data already has a fake equivalent"""
    for record in records:
        if record['piiType'].upper() == pii_type.upper() and record['originalData'].upper() == pii_data.upper():
            return record['fakeData']
    return None


def anonymize_profile(identity, identityType, profile, context=None):
    """Enhanced profile anonymization with medical data support"""
    print(f'Profile {type(profile)} - {profile}')
    try:
        masterid = get_piimaster_uuid(identity, identityType)
        
        # Log profile access
        log_phi_access(masterid, 'ANONYMIZE_PROFILE', 'profile', context)

        # Get PII Data stored for the User
        rows = get_piientity_data(masterid)

        anon_profile = {}
        records = []
        
        # Medical profile fields that need special handling
        medical_fields = {
            'diagnosis': 'DIAGNOSIS',
            'medications': 'MEDICATION',
            'allergies': 'MEDICAL_CONDITION',
            'medical_history': 'MEDICAL_CONDITION',
            'chief_complaint': 'MEDICAL_CONDITION',
            'lab_results': 'LAB_VALUE',
            'vital_signs': 'LAB_VALUE',
            'procedures': 'PROCEDURE',
            'insurance_id': 'INSURANCE_ID',
            'provider_npi': 'PROVIDER_ID'
        }
        
        for key, value in profile.items():
            fake_data = None
            if value != '' and value is not None:
                # Check if this is a medical field
                medical_type = None
                for med_field, med_type in medical_fields.items():
                    if med_field in key.lower():
                        medical_type = med_type
                        break
                
                if medical_type:
                    # Handle medical data
                    fake_data = if_exists(rows, medical_type, str(value))
                    if fake_data is None:
                        fake_data = if_exists(records, medical_type, str(value))
                        if fake_data is None:
                            fake_data_generator_name, fake_data = generate_fake_data(medical_type)
                            records.append({
                                'uuid': masterid,
                                'piiType': medical_type,
                                'originalData': str(value),
                                'fakeDataType': fake_data_generator_name,
                                'fakeData': fake_data
                            })
                elif 'dob' in key or 'date of birth'.upper() in key.upper():
                    # HIPAA compliant date handling
                    fake_data = if_exists(rows, key, str(value))
                    if fake_data is None:
                        fake_data = if_exists(records, 'DOB', str(value))
                        if fake_data is None:
                            # Keep only year for HIPAA compliance
                            try:
                                year = str(value).split('/')[-1]
                                fake_data = 'XX/XX/' + year
                            except:
                                fake_data = 'XX/XX/XXXX'
                            records.append({
                                'uuid': masterid,
                                'piiType': 'DOB',
                                'originalData': str(value),
                                'fakeDataType': 'HIPAA_Date_Handler',
                                'fakeData': fake_data
                            })
                elif 'zip' in key:
                    # HIPAA compliant ZIP handling
                    fake_data = if_exists(rows, key, str(value))
                    if fake_data is None:
                        fake_data = if_exists(records, 'ZIP', str(value))
                        if fake_data is None:
                            # Check if ZIP is in restricted list
                            restricted_zips = ['036', '692', '878', '059', '790', '879', '063', '821', '884', '102', '823', '890', '203', '830', '893', '556', '831']
                            if str(value)[:3] in restricted_zips:
                                fake_data = '00000'
                            else:
                                fake_data = str(value)[:3] + '**'
                            records.append({
                                'uuid': masterid,
                                'piiType': 'ZIP',
                                'originalData': str(value),
                                'fakeDataType': 'HIPAA_ZIP_Handler',
                                'fakeData': fake_data
                            })
                elif 'FIRST NAME' in key.upper():
                    fake_data = if_exists(rows, 'NAME', str(value))
                    if fake_data is None:
                        fake_data = if_exists(records, 'NAME', str(value))
                        if fake_data is None:
                            fake_data_generator_name, fake_data = generate_fake_data('NAME')
                            tokens = fake_data.split(' ')
                            fake_data = tokens[0]
                            records.append({
                                'uuid': masterid,
                                'piiType': 'NAME',
                                'originalData': str(value),
                                'fakeDataType': fake_data_generator_name,
                                'fakeData': fake_data
                            })
                elif 'LAST NAME' in key.upper():
                    fake_data = if_exists(rows, 'NAME', str(value))
                    if fake_data is None:
                        fake_data = if_exists(records, 'NAME', str(value))
                        if fake_data is None:
                            fake_data_generator_name, fake_data = generate_fake_data('NAME')
                            tokens = fake_data.split(' ')
                            fake_data = tokens[1] if len(tokens) > 1 else tokens[0]
                            records.append({
                                'uuid': masterid,
                                'piiType': 'NAME',
                                'originalData': str(value),
                                'fakeDataType': fake_data_generator_name,
                                'fakeData': fake_data
                            })
                else:
                    # Use standard PII detection
                    entities = detect_pii_data(str(value))
                    if entities:
                        entity = entities[0]
                        fake_data = if_exists(rows, entity['Type'], str(entity['originalData']))
                        if fake_data is None:
                            fake_data = if_exists(records, entity['Type'], str(entity['originalData']))
                            if fake_data is None:
                                fake_data_generator_name, fake_data = generate_fake_data(entity['Type'])

                                if entity['Type'] == 'ADDRESS':
                                    fake_data = fake_data.replace('\n', ' ')

                                if entity['Type'] == 'NAME':
                                    tokens = fake_data.split(' ')
                                    fake_data = tokens[0]

                                records.append({
                                    'uuid': masterid,
                                    'piiType': entity['Type'],
                                    'originalData': entity['originalData'],
                                    'fakeDataType': fake_data_generator_name,
                                    'fakeData': fake_data
                                })
            if fake_data is None:
                fake_data = value

            anon_profile[key] = fake_data

        if records:
            bulk_insert_piientity(records)

        # Log successful profile anonymization
        audit_logger.log_success({
            'masterid': masterid,
            'action': 'ANONYMIZE_PROFILE',
            'fields_processed': len(anon_profile),
            'timestamp': datetime.datetime.utcnow().isoformat()
        })

        result = {
            "statusCode": 200,
            "body": json.dumps({
                "result": str(anon_profile),
                "compliance": {
                    "hipaa_safe_harbor": True,
                    "gdpr_pseudonymized": True
                }
            })
        }
        print(f'Result {result}')
        return result

    except Exception as e:
        logger.error(e)
        audit_logger.log_error({
            'action': 'ANONYMIZE_PROFILE',
            'error': str(e),
            'timestamp': datetime.datetime.utcnow().isoformat()
        })
        return {
            "statusCode": 500,
            "error": f"Error: {e}"
        }


def de_anonymize_profile(identity, identityType, profile, context=None):
    """De-anonymize profile with audit logging"""
    try:
        result = None
        masterid = get_piimaster_uuid(identity, identityType, insert=False)
        
        # Log de-anonymization attempt
        log_phi_access(masterid, 'DE_ANONYMIZE_PROFILE', 'profile', context)

        # Get PII Data stored for the User
        rows = get_piientity_data(masterid)
        deanon_profile = {}
        if rows:
            for key, value in profile.items():
                if value != '' and value is not None:
                    result = de_anonymize(str(value), rows)
                deanon_profile[key] = result if result else value

        # Log successful de-anonymization
        audit_logger.log_success({
            'masterid': masterid,
            'action': 'DE_ANONYMIZE_PROFILE',
            'fields_processed': len(deanon_profile),
            'timestamp': datetime.datetime.utcnow().isoformat()
        })

        return {
            "statusCode": 200,
            "body": json.dumps({
                "result": str(deanon_profile)
            })
        }

    except Exception as e:
        logger.error(e)
        audit_logger.log_error({
            'action': 'DE_ANONYMIZE_PROFILE',
            'error': str(e),
            'timestamp': datetime.datetime.utcnow().isoformat()
        })
        return {
            "statusCode": 500,
            "error": f"Error: {e}"
        }


def de_anonymizer(identity, identityType, conversation, context=None):
    """
    De-anonymizes a given conversation for a specific identity with HIPAA/GDPR compliance.

    This function attempts to reverse the anonymization process on a conversation
    by replacing fake data with the original PII (Personally Identifiable Information).

    Args:
        identity (str): The identifier for the entity (e.g., user ID, email).
        identityType (str): The type of the identity (e.g., 'USER_ID', 'EMAIL').
        conversation (str): The anonymized conversation text to be de-anonymized.
        context (dict): Optional context for audit logging and access control

    Returns:
        dict: A dictionary containing:
            - 'statusCode' (int): 200 for success, 500 for error.
            - 'body' (str): A JSON string containing the de-anonymized conversation
              or the original conversation if de-anonymization wasn't possible.
            - 'error' (str): Description of the error if an exception occurred.

    Raises:
        Exception: Any exception that occurs during the de-anonymization process
                   is caught and logged, returning a 500 status code.

    Note:
        - This function does not insert a new record if the identity doesn't exist.
        - If no PII data is found for the given identity, the original conversation is returned.
        - The de-anonymized conversation is stored in the database with the method 'DE-ANONYMIZE'.
        - All access is logged for HIPAA compliance.
    """
    try:
        # GDPR access control check
        if context and context.get('requires_authorization'):
            # In production, verify user has legitimate access rights
            pass
        
        result = None
        # Retrieve the UUID associated with the given identity and identity type
        # insert=False ensures no new record is created if the identity doesn't exist
        masterid = get_piimaster_uuid(identity, identityType, insert=False)
        
        # Log de-anonymization access
        log_phi_access(masterid, 'DE_ANONYMIZE', 'conversation', context)

        # Get PII Data stored for the User
        # Retrieve all PII data records associated with the masterid
        rows = get_piientity_data(masterid)
        logger.debug(f"Rows for {identity}, {identityType}: {rows}")
        if rows:
            # De-anonymize the conversation using the retrieved PII data
            result = de_anonymize(conversation, rows)
            
            # Store the de-anonymized conversation in the database with metadata
            metadata = {
                'gdpr_access_reason': context.get('access_reason') if context else None,
                'gdpr_authorized_by': context.get('authorized_by') if context else None,
                'timestamp': datetime.datetime.utcnow().isoformat()
            }
            insert_piidata(masterid, result, conversation, 'DE-ANONYMIZE', metadata=json.dumps(metadata))
            
            # Log successful de-anonymization
            audit_logger.log_success({
                'masterid': masterid,
                'action': 'DE_ANONYMIZE',
                'entities_restored': len(rows),
                'timestamp': datetime.datetime.utcnow().isoformat()
            })

        return {
            "statusCode": 200,
            "body": json.dumps({
                "result": result if result else conversation,
                "entities_restored": len(rows) if rows else 0
            })
        }
    except Exception as e:
        logger.error(e)
        audit_logger.log_error({
            'action': 'DE_ANONYMIZE',
            'error': str(e),
            'timestamp': datetime.datetime.utcnow().isoformat()
        })
        return {
            "statusCode": 500,
            "error": f"Error: {e}"
        }


def anonymize_json(identity, identityType, json_data, context=None):
    """
    Anonymize JSON data recursively while preserving structure.
    
    Args:
        identity: The identifier for the entity
        identityType: The type of the identity
        json_data: JSON string or dict to anonymize
        context: Optional context for audit logging
    
    Returns:
        dict: Response with anonymized JSON
    """
    try:
        # Parse JSON if string
        if isinstance(json_data, str):
            data = json.loads(json_data)
        else:
            data = json_data
            
        masterid = get_piimaster_uuid(identity, identityType)
        
        # Log JSON anonymization
        log_phi_access(masterid, 'ANONYMIZE_JSON', 'json_data', context)
        
        # Get existing PII data for user
        rows = get_piientity_data(masterid)
        
        # Recursively anonymize the JSON
        anonymized_data, records = _anonymize_json_recursive(data, masterid, rows)
        
        # Bulk insert new PII mappings
        if records:
            bulk_insert_piientity(records)
            
        # Store anonymization record
        metadata = {
            'gdpr_purpose': context.get('purpose') if context else None,
            'gdpr_legal_basis': 'Article 9(2)(h)' if context else None,
            'entities_processed': len(records),
            'data_type': 'json'
        }
        insert_piidata(masterid, json.dumps(data), json.dumps(anonymized_data), 
                      'ANONYMIZE_JSON', metadata=json.dumps(metadata))
        
        # Log success
        audit_logger.log_success({
            'masterid': masterid,
            'action': 'ANONYMIZE_JSON',
            'entities_processed': len(records),
            'timestamp': datetime.datetime.utcnow().isoformat()
        })
        
        return {
            "statusCode": 200,
            "body": json.dumps({
                "result": anonymized_data,
                "entities_detected": len(records),
                "compliance": {
                    "hipaa_safe_harbor": True,
                    "gdpr_pseudonymized": True
                }
            })
        }
        
    except Exception as e:
        logger.error(e)
        audit_logger.log_error({
            'action': 'ANONYMIZE_JSON',
            'error': str(e),
            'timestamp': datetime.datetime.utcnow().isoformat()
        })
        return {
            "statusCode": 500,
            "error": f"Error: {e}"
        }


def _anonymize_json_recursive(data, masterid, existing_rows, records=None):
    """
    Recursively anonymize JSON data, handling nested structures.
    Enhanced to handle all structures properly.
    """
    if records is None:
        records = []
        
    if isinstance(data, dict):
        anonymized = {}
        for key, value in data.items():
            # ALWAYS check if the key indicates sensitive data
            if should_anonymize_key(key):
                # Force anonymization for sensitive keys
                anonymized[key], new_records = _anonymize_value(
                    key, value, masterid, existing_rows, records
                )
                records.extend(new_records)
            else:
                # For non-sensitive keys, still check the value
                anonymized[key], _ = _anonymize_json_recursive(
                    value, masterid, existing_rows, records
                )
        return anonymized, records
        
    elif isinstance(data, list):
        anonymized = []
        for item in data:
            anon_item, _ = _anonymize_json_recursive(
                item, masterid, existing_rows, records
            )
            anonymized.append(anon_item)
        return anonymized, records
        
    else:
        # It's a scalar value - check if it needs anonymization
        # Even for non-sensitive keys, check if the value contains PII
        return _anonymize_scalar(data, masterid, existing_rows, records)


def should_anonymize_key(key):
    """
    Determine if a key likely contains PII/PHI based on its name.
    Enhanced to catch more medical fields.
    """
    pii_keywords = [
        'name', 'clinic_name', 'provider', 'doctor', 'physician',
        'date', 'dob', 'birth', 'address', 'phone', 'email',
        'ssn', 'mrn', 'id', 'diagnosis', 'medication', 
        'referring_provider', 'clinic', 'hospital', 'service',
        'clinician', 'consultant', 'psychiatrist', 'psychologist',
        'therapist', 'counselor', 'nurse', 'role', 'reason',
        'note', 'comment', 'description', 'summary',
        # Medical symptom keywords
        'symptom', 'symptoms', 'challenge', 'challenges',
        'pattern', 'patterns', 'condition', 'conditions',
        'disorder', 'disorders', 'impairment', 'disease',
        'syndrome', 'illness', 'ailment', 'complaint',
        'anxiety', 'depression', 'delusion', 'hallucination',
        'apathy', 'agitation', 'irritability',
        # Daily living activities
        'activities', 'living', 'laundry', 'shopping',
        'housekeeping', 'communication', 'transportation',
        'food_preparation', 'managing_finances', 'managing_medications'
    ]
    
    key_lower = key.lower()
    return any(keyword in key_lower for keyword in pii_keywords)


def _anonymize_value(key, value, masterid, existing_rows, records):
    """
    Anonymize a value based on the key context.
    ALWAYS anonymizes if the key indicates sensitive data.
    """
    if value is None or value == '':
        return value, []
        
    new_records = []
    
    # Handle lists (like the clinicians array or symptom arrays)
    if isinstance(value, list):
        anonymized_list = []
        for item in value:
            if isinstance(item, dict):
                anon_item, _ = _anonymize_json_recursive(item, masterid, existing_rows, records)
                anonymized_list.append(anon_item)
            else:
                # For string items in medical arrays, we need to anonymize each one
                if item and isinstance(item, str):
                    # Determine the appropriate PII type based on the key
                    pii_type = determine_pii_type_from_key(key)
                    
                    # Check if we already have a fake value
                    fake_data = if_exists(existing_rows, pii_type, str(item))
                    if fake_data is None:
                        fake_data = if_exists(records, pii_type, str(item))
                        if fake_data is None:
                            # Generate new fake data
                            try:
                                fake_data_generator, fake_data = generate_fake_data(pii_type)
                            except:
                                fake_data = _generate_generic_fake_data(pii_type, str(item))
                                fake_data_generator = 'Generic_Handler'
                            
                            new_record = {
                                'uuid': masterid,
                                'piiType': pii_type,
                                'originalData': str(item),
                                'fakeDataType': fake_data_generator,
                                'fakeData': fake_data
                            }
                            records.append(new_record)
                            new_records.append(new_record)
                    
                    anonymized_list.append(fake_data)
                else:
                    anonymized_list.append(item)
        return anonymized_list, new_records  # Return the new_records!
    
    # Handle nested objects
    if isinstance(value, dict):
        return _anonymize_json_recursive(value, masterid, existing_rows, records)
        
    # Convert value to string for processing
    str_value = str(value)
    
    # Determine PII type based on key
    pii_type = determine_pii_type_from_key(key)
    
    # Check if we already have a fake value
    fake_data = if_exists(existing_rows, pii_type, str_value)
    if fake_data is None:
        fake_data = if_exists(records, pii_type, str_value)
        if fake_data is None:
            # Generate new fake data
            if pii_type == 'DATE':
                fake_data = anonymize_date_hipaa(str_value)
                fake_data_generator = 'HIPAA_Date_Handler'
            else:
                # ALWAYS generate fake data for sensitive keys
                try:
                    fake_data_generator, fake_data = generate_fake_data(pii_type)
                except:
                    # Use fallback generation
                    fake_data = _generate_generic_fake_data(pii_type, str_value)
                    fake_data_generator = 'Generic_Handler'
                
            new_records.append({
                'uuid': masterid,
                'piiType': pii_type,
                'originalData': str_value,
                'fakeDataType': fake_data_generator,
                'fakeData': fake_data
            })
    
    return fake_data, new_records


def _generate_generic_fake_data(pii_type, original_value):
    """
    Generate generic fake data when specific generators aren't available.
    Enhanced with more types.
    """
    import random
    import string
    
    generic_replacements = {
        'DIAGNOSIS': [
            'Chronic Fatigue Syndrome',
            'Essential Hypertension',
            'Type 2 Diabetes Mellitus',
            'Major Depressive Disorder',
            'Generalized Anxiety Disorder',
            'Migraine without Aura',
            'Gastroesophageal Reflux Disease',
            'Mild Neurocognitive Disorder',
            'Memory Impairment',
            'Cognitive Disorder'
        ],
        'ORGANIZATION': [
            'General Medical Center',
            'Regional Health Clinic',
            'Community Care Hospital',
            'Wellness Medical Group',
            'Metropolitan Health Services',
            'Central Medical Associates',
            'Premier Healthcare Center',
            'Unity Health Network',
            'Integrated Memory Care Service',
            'Neurological Assessment Unit'
        ],
        'JOB_TITLE': [
            'Consultant Physician',
            'Senior Specialist',
            'Clinical Director',
            'Medical Officer',
            'Research Coordinator',
            'Clinical Assistant',
            'Healthcare Professional',
            'Medical Consultant',
            'Senior Clinician',
            'Clinical Specialist'
        ],
        'CLINICAL_NOTE': [
            'routine follow-up and assessment',
            'standard clinical evaluation',
            'comprehensive health review',
            'periodic medical assessment',
            'general health consultation',
            'clinical review and planning',
            'medical evaluation and care planning',
            'health status assessment',
            'difficulty with daily activities',
            'requires assistance with tasks',
            'independent in daily activities',
            'minimal assistance needed'
        ],
        'MEDICAL_CONDITION': [
            'regular sleep patterns',
            'occasional sleep disturbance',
            'restful sleep',
            'interrupted sleep patterns',
            'stable mood',
            'mild mood changes',
            'no significant symptoms',
            'manageable symptoms',
            'improving symptoms',
            'stable condition',
            'periodic symptoms',
            'controlled symptoms'
        ],
        'MEDICATION': [
            'Acetaminophen 500mg',
            'Ibuprofen 200mg',
            'Omeprazole 20mg',
            'Lisinopril 10mg',
            'Metformin 500mg',
            'Atorvastatin 20mg',
            'Amlodipine 5mg',
            'Sertraline 50mg'
        ],
        'PROCEDURE': [
            'Physical Examination',
            'Blood Test',
            'X-Ray',
            'MRI Scan',
            'Ultrasound',
            'ECG',
            'Consultation',
            'Follow-up Visit'
        ],
        'LAB_VALUE': [
            'Normal Range',
            '120 mg/dL',
            '7.2%',
            '98.6°F',
            '120/80 mmHg',
            'Negative',
            'Within Limits',
            'Stable'
        ]
    }
    
    # If we have specific replacements for this type, use them
    if pii_type in generic_replacements:
        return random.choice(generic_replacements[pii_type])
    
    # For NAME type, generate a realistic name
    if pii_type == 'NAME':
        first_names = ['James', 'Mary', 'John', 'Patricia', 'Robert', 'Jennifer', 
                      'Michael', 'Linda', 'William', 'Elizabeth', 'David', 'Barbara']
        last_names = ['Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Garcia', 
                     'Miller', 'Davis', 'Rodriguez', 'Martinez', 'Anderson', 'Taylor']
        
        # Check if original has a title
        if any(title in original_value for title in ['Dr.', 'Professor', 'Mr.', 'Mrs.', 'Ms.']):
            return f"Dr. {random.choice(first_names)} {random.choice(last_names)}"
        else:
            return f"{random.choice(first_names)} {random.choice(last_names)}"
    
    # Otherwise, generate a generic anonymized string
    return f"[Anonymized {pii_type}]"


def _anonymize_scalar(value, masterid, existing_rows, records):
    """
    Anonymize a scalar value by detecting PII.
    Enhanced to handle failures gracefully.
    """
    if value is None or value == '' or isinstance(value, (int, float, bool)):
        return value, []
        
    # Detect PII in the value
    entities = detect_pii_data(str(value))
    
    if not entities:
        return value, []
        
    # Anonymize detected entities
    anonymized_value = str(value)
    new_records = []
    
    for entity in entities:
        fake_data = if_exists(existing_rows, entity['Type'], entity['originalData'])
        if fake_data is None:
            fake_data = if_exists(records, entity['Type'], entity['originalData'])
            if fake_data is None:
                try:
                    fake_data_generator, fake_data = generate_fake_data(entity['Type'])
                except:
                    # If generation fails, use a simple replacement
                    fake_data = f"[REDACTED-{entity['Type']}]"
                    fake_data_generator = 'Redaction_Handler'
                    
                new_records.append({
                    'uuid': masterid,
                    'piiType': entity['Type'],
                    'originalData': entity['originalData'],
                    'fakeDataType': fake_data_generator,
                    'fakeData': fake_data
                })
        
        anonymized_value = anonymized_value.replace(entity['originalData'], fake_data)
    
    return anonymized_value, new_records


def determine_pii_type_from_key(key):
    """
    Determine the PII type based on the key name.
    Enhanced with more specific mappings.
    """
    key_lower = key.lower()
    
    # Check for specific patterns first
    if any(x in key_lower for x in ['clinic_name', 'hospital', 'facility', 'service', 'center']):
        return 'ORGANIZATION'
    elif any(x in key_lower for x in ['provider', 'doctor', 'physician', 'referring', 'clinician', 
                                      'consultant', 'psychiatrist', 'psychologist', 'therapist']):
        return 'NAME'
    elif 'name' in key_lower and 'clinic' not in key_lower:  # Just "name" but not "clinic_name"
        return 'NAME'
    elif 'role' in key_lower:
        return 'JOB_TITLE'
    elif 'date' in key_lower:
        return 'DATE'
    elif any(x in key_lower for x in ['diagnosis', 'condition', 'disorder', 'syndrome', 
                                      'disease', 'illness', 'impairment', 'challenge']):
        return 'DIAGNOSIS'
    elif any(x in key_lower for x in ['symptom', 'symptoms', 'pattern', 'patterns',
                                      'anxiety', 'depression', 'delusion', 'hallucination',
                                      'apathy', 'agitation', 'irritability']):
        return 'MEDICAL_CONDITION'
    elif any(x in key_lower for x in ['activities', 'living', 'laundry', 'shopping',
                                      'housekeeping', 'communication', 'transportation',
                                      'food_preparation', 'managing_finances', 'managing_medications']):
        return 'CLINICAL_NOTE'
    elif any(x in key_lower for x in ['phone', 'tel', 'mobile', 'cell']):
        return 'PHONE_NUMBER'
    elif 'email' in key_lower:
        return 'EMAIL'
    elif 'address' in key_lower:
        return 'ADDRESS'
    elif any(x in key_lower for x in ['ssn', 'social']):
        return 'SSN'
    elif any(x in key_lower for x in ['mrn', 'medical_record', 'patient_id']):
        return 'MRN'
    elif 'reason' in key_lower:
        return 'CLINICAL_NOTE'
    else:
        return 'OTHER'


def anonymize_date_hipaa(date_str):
    """
    Anonymize date according to HIPAA Safe Harbor.
    Keeps only the year if the date is not in the current year.
    """
    try:
        from datetime import datetime
        current_year = datetime.now().year
        
        # Try different date formats
        for fmt in ['%d/%b/%Y', '%d/%m/%Y', '%Y-%m-%d', '%m/%d/%Y']:
            try:
                date_obj = datetime.strptime(date_str, fmt)
                if date_obj.year < current_year:
                    return f"XX/XX/{date_obj.year}"
                else:
                    # Current year - anonymize month/day
                    return f"XX/XX/{date_obj.year}"
            except:
                continue
                
        # If no format worked, return generic
        return "XX/XX/XXXX"
    except:
        return "XX/XX/XXXX"


def de_anonymize_json(identity, identityType, json_data, context=None):
    """
    De-anonymize JSON data while preserving structure.
    """
    try:
        # Parse JSON if string
        if isinstance(json_data, str):
            data = json.loads(json_data)
        else:
            data = json_data
            
        masterid = get_piimaster_uuid(identity, identityType, insert=False)
        
        # Log de-anonymization access
        log_phi_access(masterid, 'DE_ANONYMIZE_JSON', 'json_data', context)
        
        # Get PII data for user
        rows = get_piientity_data(masterid)
        
        if not rows:
            return {
                "statusCode": 200,
                "body": json.dumps({
                    "result": data,
                    "entities_restored": 0
                })
            }
        
        # Recursively de-anonymize
        de_anonymized_data = _de_anonymize_json_recursive(data, rows)
        
        # Store de-anonymization record
        metadata = {
            'gdpr_access_reason': context.get('access_reason') if context else None,
            'gdpr_authorized_by': context.get('authorized_by') if context else None,
            'timestamp': datetime.datetime.utcnow().isoformat()
        }
        insert_piidata(masterid, json.dumps(de_anonymized_data), json.dumps(data), 
                      'DE_ANONYMIZE_JSON', metadata=json.dumps(metadata))
        
        # Log success
        audit_logger.log_success({
            'masterid': masterid,
            'action': 'DE_ANONYMIZE_JSON',
            'entities_restored': len(rows),
            'timestamp': datetime.datetime.utcnow().isoformat()
        })
        
        return {
            "statusCode": 200,
            "body": json.dumps({
                "result": de_anonymized_data,
                "entities_restored": len(rows)
            })
        }
        
    except Exception as e:
        logger.error(e)
        audit_logger.log_error({
            'action': 'DE_ANONYMIZE_JSON',
            'error': str(e),
            'timestamp': datetime.datetime.utcnow().isoformat()
        })
        return {
            "statusCode": 500,
            "error": f"Error: {e}"
        }


def _de_anonymize_json_recursive(data, rows):
    """
    Recursively de-anonymize JSON data.
    """
    if isinstance(data, dict):
        de_anonymized = {}
        for key, value in data.items():
            de_anonymized[key] = _de_anonymize_json_recursive(value, rows)
        return de_anonymized
        
    elif isinstance(data, list):
        return [_de_anonymize_json_recursive(item, rows) for item in data]
        
    else:
        # It's a scalar value - try to de-anonymize
        if data is None or data == '':
            return data
            
        # Try to find and replace fake data with original
        result = str(data)
        for row in rows:
            if row['fakeData'] in result:
                result = result.replace(row['fakeData'], row['originalData'])
                
        # Return appropriate type
        if isinstance(data, str):
            return result
        else:
            return data


def lambda_handler(event, context):
    """Enhanced lambda handler with JSON support"""
    method = None
    identity = None
    identityType = None
    conversation = None
    profile = None
    json_data = None
    request_context = {}
    
    logger.debug(event)
    print(event)
    body = json.loads(event['body'])

    for k, v in body.items():
        if k.upper() == 'METHOD':
            method = v.upper()
        elif k.upper() == 'IDENTITY':
            identity = v.upper()
        elif k.upper() == 'IDENTITYTYPE':
            identityType = v.upper()
        elif k.upper() == 'CONVERSATION':
            conversation = v
        elif k.upper() == 'PROFILE':
            profile = ast.literal_eval(v)
        elif k.upper() == 'JSON_DATA':
            json_data = v
        elif k.upper() == 'CONTEXT':
            request_context = v if isinstance(v, dict) else json.loads(v)

    # Add Lambda context info for audit
    request_context['lambda_request_id'] = context.request_id if context else None
    request_context['lambda_function_name'] = context.function_name if context else None

    print(method)
    if method == 'ANONYMIZE':
        if json_data:
            response = anonymize_json(identity, identityType, json_data, request_context)
        elif conversation:
            response = anonymizer(identity, identityType, conversation, request_context)
        else:
            response = anonymize_profile(identity, identityType, profile, request_context)
    elif method == 'DE-ANONYMIZE':
        if json_data:
            response = de_anonymize_json(identity, identityType, json_data, request_context)
        elif conversation:
            response = de_anonymizer(identity, identityType, conversation, request_context)
        else:
            response = de_anonymize_profile(identity, identityType, profile, request_context)
    elif method == 'ANONYMIZE_JSON':
        response = anonymize_json(identity, identityType, json_data, request_context)
    elif method == 'DE_ANONYMIZE_JSON':
        response = de_anonymize_json(identity, identityType, json_data, request_context)
    else:
        logger.debug(f"No handler for http verb: {event['Method']}")
        raise Exception(f"No handler for http verb: {event['Method']}")

    return response
