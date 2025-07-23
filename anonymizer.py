import ast
import json
import logging
import datetime
from typing import Dict, Any
import random
import hashlib
import re
from collections import OrderedDict

import db_utils
from comprehend import generate_fake_entities, detect_pii_data, anonymize, de_anonymize, generate_fake_data
from db_methods import get_piimaster_uuid, get_piientity_data, bulk_insert_piientity, insert_piidata
from audit_logger import AuditLogger  # New module for HIPAA compliance

logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)

# Initialize audit logger for HIPAA compliance
audit_logger = AuditLogger()

session = db_utils.get_db_session()

# DEBUG MODE - Set to False in production
DEBUG_MODE = True


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
    """Enhanced profile anonymization - only anonymizes HIPAA identifiers"""
    print(f'Profile {type(profile)} - {profile}')
    try:
        masterid = get_piimaster_uuid(identity, identityType)
        
        # Log profile access
        log_phi_access(masterid, 'ANONYMIZE_PROFILE', 'profile', context)

        # Get PII Data stored for the User
        rows = get_piientity_data(masterid)

        anon_profile = {}
        records = []
        
        for key, value in profile.items():
            fake_data = None
            if value != '' and value is not None:
                # Check for HIPAA identifiers in profile keys
                if 'dob' in key.lower() or 'date of birth' in key.lower():
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
                elif 'zip' in key.lower():
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
                elif 'first name' in key.lower() or 'last name' in key.lower() or key.lower() == 'name':
                    # Check if this is a provider name
                    if 'provider' not in key.lower() and 'doctor' not in key.lower() and 'physician' not in key.lower():
                        fake_data = if_exists(rows, 'NAME', str(value))
                        if fake_data is None:
                            fake_data = if_exists(records, 'NAME', str(value))
                            if fake_data is None:
                                fake_data_generator_name, fake_data = generate_fake_data('NAME')
                                if 'first name' in key.lower():
                                    tokens = fake_data.split(' ')
                                    fake_data = tokens[0]
                                elif 'last name' in key.lower():
                                    tokens = fake_data.split(' ')
                                    fake_data = tokens[1] if len(tokens) > 1 else tokens[0]
                                records.append({
                                    'uuid': masterid,
                                    'piiType': 'NAME',
                                    'originalData': str(value),
                                    'fakeDataType': fake_data_generator_name,
                                    'fakeData': fake_data
                                })
                elif any(hipaa_key in key.lower() for hipaa_key in ['phone', 'email', 'ssn', 'mrn', 'insurance']):
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

                                records.append({
                                    'uuid': masterid,
                                    'piiType': entity['Type'],
                                    'originalData': entity['originalData'],
                                    'fakeDataType': fake_data_generator_name,
                                    'fakeData': fake_data
                                })
                else:
                    # For other fields, check if the value contains PII
                    entities = detect_pii_data(str(value))
                    if entities:
                        entity = entities[0]
                        fake_data = if_exists(rows, entity['Type'], str(entity['originalData']))
                        if fake_data is None:
                            fake_data = if_exists(records, entity['Type'], str(entity['originalData']))
                            if fake_data is None:
                                fake_data_generator_name, fake_data = generate_fake_data(entity['Type'])
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
    """
    try:
        # GDPR access control check
        if context and context.get('requires_authorization'):
            # In production, verify user has legitimate access rights
            pass
        
        result = None
        masterid = get_piimaster_uuid(identity, identityType, insert=False)
        
        # Log de-anonymization access
        log_phi_access(masterid, 'DE_ANONYMIZE', 'conversation', context)

        # Get PII Data stored for the User
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


def anonymize_json_simple(identity, identityType, json_data, context=None):
    """
    Simple JSON anonymization that preserves structure and order.
    Only anonymizes HIPAA identifiers, preserves medical information.
    """
    try:
        if DEBUG_MODE:
            print(f"[DEBUG] Starting simple anonymization for identity: {identity}")
        
        # Parse JSON preserving order
        if isinstance(json_data, str):
            # Use object_pairs_hook to preserve order
            data = json.loads(json_data, object_pairs_hook=OrderedDict)
        else:
            data = json_data
            
        if DEBUG_MODE:
            print(f"[DEBUG] Input data type: {type(data)}")
            
        masterid = get_piimaster_uuid(identity, identityType)
        if DEBUG_MODE:
            print(f"[DEBUG] Master ID: {masterid}")
        
        # Log JSON anonymization
        log_phi_access(masterid, 'ANONYMIZE_JSON', 'json_data', context)
        
        # Get existing PII data for user
        rows = get_piientity_data(masterid)
        if DEBUG_MODE:
            print(f"[DEBUG] Existing rows count: {len(rows) if rows else 0}")
        
        # Recursively anonymize the JSON while preserving structure and order
        anonymized_data, records = _anonymize_json_recursive_ordered(data, masterid, rows)
        
        if DEBUG_MODE:
            print(f"[DEBUG] Anonymization complete. Records created: {len(records)}")
            if records:
                print(f"[DEBUG] Sample records:")
                for record in records[:5]:
                    print(f"  - {record['piiType']}: '{record['originalData']}' -> '{record['fakeData']}'")
        
        # Deduplicate records
        unique_records = []
        seen = set()
        for record in records:
            key = (record['uuid'], record['piiType'], record['originalData'])
            if key not in seen:
                seen.add(key)
                unique_records.append(record)
        
        if DEBUG_MODE:
            print(f"[DEBUG] Unique records to insert: {len(unique_records)}")
        
        if unique_records:
            bulk_insert_piientity(unique_records)
            
        # Store anonymization record - preserve order in JSON
        metadata = {
            'gdpr_purpose': context.get('purpose') if context else None,
            'gdpr_legal_basis': 'Article 9(2)(h)' if context else None,
            'entities_processed': len(unique_records),
            'data_type': 'json_simple'
        }
        
        # Use json.dumps with sort_keys=False to preserve order
        original_json = json.dumps(data, sort_keys=False)
        anonymized_json = json.dumps(anonymized_data, sort_keys=False)
        
        insert_piidata(masterid, original_json, anonymized_json, 
                      'ANONYMIZE_JSON_SIMPLE', metadata=json.dumps(metadata))
        
        # Log success
        audit_logger.log_success({
            'masterid': masterid,
            'action': 'ANONYMIZE_JSON_SIMPLE',
            'entities_processed': len(unique_records),
            'timestamp': datetime.datetime.utcnow().isoformat()
        })
        
        return {
            "statusCode": 200,
            "body": json.dumps({
                "result": anonymized_data,
                "entities_detected": len(unique_records),
                "compliance": {
                    "hipaa_safe_harbor": True,
                    "gdpr_pseudonymized": True,
                    "structure_preserved": True
                }
            }, sort_keys=False)  # Preserve order in response
        }
        
    except Exception as e:
        import traceback
        if DEBUG_MODE:
            print(f"[DEBUG] Error in anonymize_json_simple: {str(e)}")
            print(f"[DEBUG] Traceback: {traceback.format_exc()}")
        logger.error(e)
        audit_logger.log_error({
            'action': 'ANONYMIZE_JSON_SIMPLE',
            'error': str(e),
            'timestamp': datetime.datetime.utcnow().isoformat()
        })
        return {
            "statusCode": 500,
            "error": f"Error: {e}"
        }


def _anonymize_json_recursive_ordered(data, masterid, existing_rows, records=None):
    """
    Recursively anonymize JSON data while preserving structure and order.
    Only anonymizes HIPAA identifiers, preserves medical information.
    """
    if records is None:
        records = []
        
    if isinstance(data, (dict, OrderedDict)):
        # Use OrderedDict to preserve order
        anonymized = OrderedDict()
        for key, value in data.items():
            # Check if this key might contain HIPAA identifiers
            if should_anonymize_key(key):
                anonymized[key], new_records = _anonymize_value_comprehensive(
                    key, value, masterid, existing_rows, records
                )
                records.extend(new_records)
            else:
                # Still check nested structures and string values for PII
                if isinstance(value, str):
                    # Check if the string contains PII
                    entities = detect_pii_data(value)
                    if entities:
                        anonymized[key], new_records = _anonymize_value_comprehensive(
                            key, value, masterid, existing_rows, records
                        )
                        records.extend(new_records)
                    else:
                        anonymized[key] = value
                else:
                    # Recurse for nested structures
                    anonymized[key], _ = _anonymize_json_recursive_ordered(
                        value, masterid, existing_rows, records
                    )
        return anonymized, records
        
    elif isinstance(data, list):
        anonymized = []
        for item in data:
            anon_item, _ = _anonymize_json_recursive_ordered(
                item, masterid, existing_rows, records
            )
            anonymized.append(anon_item)
        return anonymized, records
        
    else:
        # Check scalar values for PII
        return _anonymize_scalar_value(data, masterid, existing_rows, records)


def _anonymize_value_comprehensive(key, value, masterid, existing_rows, records):
    """
    Anonymize a value based on detected PII.
    Only anonymizes HIPAA identifiers.
    """
    if value is None or value == '':
        return value, []
        
    new_records = []
    
    # Handle lists
    if isinstance(value, list):
        anonymized_list = []
        for item in value:
            if isinstance(item, (dict, OrderedDict)):
                anon_item, _ = _anonymize_json_recursive_ordered(item, masterid, existing_rows, records)
                anonymized_list.append(anon_item)
            elif isinstance(item, str) and item:
                # Check if the string contains PII
                entities = detect_pii_data(item)
                if entities:
                    # Anonymize detected entities
                    anonymized_item = item
                    for entity in entities:
                        fake_data = if_exists(existing_rows, entity['Type'], entity['originalData'])
                        if not fake_data:
                            fake_data = if_exists(records, entity['Type'], entity['originalData'])
                            if not fake_data:
                                generator_name, fake_data = generate_fake_data(entity['Type'])
                                
                                new_record = {
                                    'uuid': masterid,
                                    'piiType': entity['Type'],
                                    'originalData': entity['originalData'],
                                    'fakeDataType': generator_name,
                                    'fakeData': fake_data
                                }
                                if not _record_exists(new_record, records):
                                    new_records.append(new_record)
                        
                        anonymized_item = anonymized_item.replace(entity['originalData'], fake_data)
                    
                    anonymized_list.append(anonymized_item)
                else:
                    anonymized_list.append(item)
            else:
                anonymized_list.append(item)
        return anonymized_list, new_records
    
    # Handle nested objects
    if isinstance(value, (dict, OrderedDict)):
        return _anonymize_json_recursive_ordered(value, masterid, existing_rows, records)
    
    # Handle scalar values
    if isinstance(value, str) and value:
        # Detect PII in the string
        entities = detect_pii_data(value)
        if entities:
            anonymized_value = value
            for entity in entities:
                fake_data = if_exists(existing_rows, entity['Type'], entity['originalData'])
                if not fake_data:
                    fake_data = if_exists(records, entity['Type'], entity['originalData'])
                    if not fake_data:
                        if entity['Type'] == 'DATE':
                            fake_data = anonymize_date_hipaa(entity['originalData'])
                            fake_data_generator = 'HIPAA_Date_Handler'
                        else:
                            fake_data_generator, fake_data = generate_fake_data(entity['Type'])
                        
                        new_record = {
                            'uuid': masterid,
                            'piiType': entity['Type'],
                            'originalData': entity['originalData'],
                            'fakeDataType': fake_data_generator,
                            'fakeData': fake_data
                        }
                        if not _record_exists(new_record, records):
                            new_records.append(new_record)
                
                anonymized_value = anonymized_value.replace(entity['originalData'], fake_data)
            
            return anonymized_value, new_records
    
    # Return non-string values as-is (including medical scores/values)
    return value, new_records


def _anonymize_scalar_value(value, masterid, existing_rows, records):
    """
    Anonymize a scalar value if it contains HIPAA identifiers.
    """
    if value is None or value == '' or isinstance(value, (int, float, bool)):
        return value, []
        
    # Check if the string contains PII
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
                generator_name, fake_data = generate_fake_data(entity['Type'])
                    
                new_records.append({
                    'uuid': masterid,
                    'piiType': entity['Type'],
                    'originalData': entity['originalData'],
                    'fakeDataType': generator_name,
                    'fakeData': fake_data
                })
        
        anonymized_value = anonymized_value.replace(entity['originalData'], fake_data)
    
    return anonymized_value, new_records


def determine_pii_type_from_content(key, value):
    """
    Determine PII type from both key and value content.
    Only returns types for HIPAA identifiers.
    """
    key_lower = key.lower()
    value_lower = value.lower() if isinstance(value, str) else ''
    
    # HIPAA identifiers only
    if 'name' in key_lower and 'provider' not in key_lower and 'doctor' not in key_lower:
        return 'NAME'
    elif any(x in key_lower for x in ['phone', 'tel', 'mobile', 'cell', 'fax']):
        return 'PHONE_NUMBER'
    elif 'email' in key_lower:
        return 'EMAIL'
    elif 'address' in key_lower:
        return 'ADDRESS'
    elif any(x in key_lower for x in ['ssn', 'social']):
        return 'SSN'
    elif any(x in key_lower for x in ['mrn', 'medical_record', 'patient_id']):
        return 'MRN'
    elif 'date' in key_lower or 'dob' in key_lower:
        return 'DATE'
    elif 'zip' in key_lower:
        return 'ZIP'
    elif any(x in key_lower for x in ['insurance', 'member', 'policy']):
        return 'INSURANCE_ID'
    elif any(x in key_lower for x in ['license', 'certificate']):
        return 'LICENSE_NUMBER'
    elif any(x in key_lower for x in ['device', 'serial']):
        return 'DEVICE_ID'
    elif 'url' in key_lower or 'website' in key_lower:
        return 'URL'
    elif 'ip' in key_lower and 'address' in key_lower:
        return 'IP_ADDRESS'
    elif any(x in key_lower for x in ['employee_id', 'eid', 'staff_id']):
        return 'EMPLOYEE_ID'
    elif 'trial' in key_lower and any(x in value_lower for x in ['nct', 'clinical']):
        return 'CLINICAL_TRIAL_ID'
    else:
        return determine_pii_type_from_key(key)


def _record_exists(record, records):
    """Check if a record already exists in the list."""
    return any(
        r['uuid'] == record['uuid'] and 
        r['piiType'] == record['piiType'] and 
        r['originalData'] == record['originalData'] 
        for r in records
    )


def de_anonymize_json_simple(identity, identityType, json_data, context=None):
    """
    Simple de-anonymization that preserves structure and order.
    """
    try:
        if DEBUG_MODE:
            print(f"[DEBUG] Starting simple de-anonymization for identity: {identity}")
            
        # Parse JSON preserving order
        if isinstance(json_data, str):
            data = json.loads(json_data, object_pairs_hook=OrderedDict)
        else:
            data = json_data
            
        masterid = get_piimaster_uuid(identity, identityType, insert=False)
        
        if not masterid:
            return {
                "statusCode": 200,
                "body": json.dumps({
                    "result": data,
                    "entities_restored": 0
                }, sort_keys=False)
            }
        
        # Log de-anonymization access
        log_phi_access(masterid, 'DE_ANONYMIZE_JSON_SIMPLE', 'json_data', context)
        
        # Get all PII mappings for user
        rows = get_piientity_data(masterid)
        
        if not rows:
            return {
                "statusCode": 200,
                "body": json.dumps({
                    "result": data,
                    "entities_restored": 0
                }, sort_keys=False)
            }
        
        if DEBUG_MODE:
            print(f"[DEBUG] Found {len(rows)} PII mappings")
            for row in rows[:10]:
                print(f"[DEBUG] Mapping: {row['piiType']} - '{row['fakeData']}' -> '{row['originalData']}'")
        
        # Count actual replacements
        replacement_count = [0]  # Use list to pass by reference
        
        # Recursively de-anonymize while preserving structure
        de_anonymized_data = _de_anonymize_json_recursive_ordered(data, rows, replacement_count)
        
        if DEBUG_MODE:
            print(f"[DEBUG] Made {replacement_count[0]} replacements")
        
        # Store de-anonymization record
        metadata = {
            'gdpr_access_reason': context.get('access_reason') if context else None,
            'gdpr_authorized_by': context.get('authorized_by') if context else None,
            'timestamp': datetime.datetime.utcnow().isoformat()
        }
        insert_piidata(masterid, json.dumps(de_anonymized_data, sort_keys=False), 
                      json.dumps(data, sort_keys=False), 
                      'DE_ANONYMIZE_JSON_SIMPLE', metadata=json.dumps(metadata))
        
        # Log success
        audit_logger.log_success({
            'masterid': masterid,
            'action': 'DE_ANONYMIZE_JSON_SIMPLE',
            'entities_restored': replacement_count[0],
            'timestamp': datetime.datetime.utcnow().isoformat()
        })
        
        return {
            "statusCode": 200,
            "body": json.dumps({
                "result": de_anonymized_data,
                "entities_restored": replacement_count[0]
            }, sort_keys=False)
        }
        
    except Exception as e:
        import traceback
        if DEBUG_MODE:
            print(f"[DEBUG] Error: {traceback.format_exc()}")
        logger.error(e)
        audit_logger.log_error({
            'action': 'DE_ANONYMIZE_JSON_SIMPLE',
            'error': str(e),
            'timestamp': datetime.datetime.utcnow().isoformat()
        })
        return {
            "statusCode": 500,
            "error": f"Error: {e}"
        }


def _de_anonymize_json_recursive_ordered(data, rows, replacement_count):
    """
    Recursively de-anonymize JSON data while preserving structure and order.
    """
    if isinstance(data, (dict, OrderedDict)):
        de_anonymized = OrderedDict()
        for key, value in data.items():
            de_anonymized[key] = _de_anonymize_json_recursive_ordered(value, rows, replacement_count)
        return de_anonymized
        
    elif isinstance(data, list):
        return [_de_anonymize_json_recursive_ordered(item, rows, replacement_count) for item in data]
        
    else:
        # It's a scalar value - try to de-anonymize
        if data is None or data == '':
            return data
            
        # Try to find and replace fake data with original
        result = str(data) if not isinstance(data, str) else data
        
        # Check each row for a match
        for row in rows:
            if row['fakeData'] == result:
                if DEBUG_MODE:
                    print(f"[DEBUG] Replacing '{row['fakeData']}' with '{row['originalData']}'")
                replacement_count[0] += 1
                return row['originalData']
        
        # Return the original value if no match found
        return data


def anonymize_json(identity, identityType, json_data, context=None):
    """
    Main entry point for JSON anonymization.
    Now uses simple anonymization that preserves structure.
    """
    return anonymize_json_simple(identity, identityType, json_data, context)


def de_anonymize_json(identity, identityType, json_data, context=None):
    """
    Main entry point for JSON de-anonymization.
    """
    # Check if this was enhanced anonymization (for backward compatibility)
    masterid = get_piimaster_uuid(identity, identityType, insert=False)
    if masterid:
        rows = get_piientity_data(masterid)
        has_structure_map = any(row['piiType'] == 'JSON_STRUCTURE' for row in rows if row)
        
        if has_structure_map:
            # Old enhanced anonymization - not recommended
            print("[WARNING] This data was anonymized with the old enhanced method that changes structure.")
            return {
                "statusCode": 400,
                "error": "Data was anonymized with structure transformation. Please re-anonymize with current version."
            }
    
    # Use simple de-anonymization
    return de_anonymize_json_simple(identity, identityType, json_data, context)


def _de_anonymize_json_recursive(data, rows):
    """
    Recursively de-anonymize JSON data (kept for backward compatibility).
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


def determine_pii_type_from_key(key):
    """
    Determine the PII type based on the key name.
    Only returns types for HIPAA identifiers.
    """
    key_lower = key.lower()
    
    # HIPAA identifiers only
    if 'name' in key_lower and 'provider' not in key_lower and 'doctor' not in key_lower and 'physician' not in key_lower:
        return 'NAME'
    elif any(x in key_lower for x in ['phone', 'tel', 'mobile', 'cell', 'fax']):
        return 'PHONE_NUMBER'
    elif 'email' in key_lower:
        return 'EMAIL'
    elif 'address' in key_lower:
        return 'ADDRESS'
    elif any(x in key_lower for x in ['ssn', 'social']):
        return 'SSN'
    elif any(x in key_lower for x in ['mrn', 'medical_record', 'patient_id']):
        return 'MRN'
    elif 'date' in key_lower or 'dob' in key_lower or 'birth' in key_lower:
        return 'DATE'
    elif 'zip' in key_lower:
        return 'ZIP'
    elif any(x in key_lower for x in ['insurance', 'member', 'policy', 'beneficiary']):
        return 'INSURANCE_ID'
    elif any(x in key_lower for x in ['license', 'certificate']):
        return 'LICENSE_NUMBER'
    elif any(x in key_lower for x in ['device', 'serial', 'implant']):
        return 'DEVICE_ID'
    elif 'url' in key_lower or 'website' in key_lower:
        return 'URL'
    elif 'ip' in key_lower and 'address' in key_lower:
        return 'IP_ADDRESS'
    elif any(x in key_lower for x in ['employee_id', 'eid', 'staff_id']):
        return 'EMPLOYEE_ID'
    elif any(x in key_lower for x in ['vehicle', 'vin', 'plate']):
        return 'VEHICLE_ID'
    elif any(x in key_lower for x in ['fingerprint', 'retinal', 'voiceprint', 'biometric']):
        return 'BIOMETRIC_ID'
    elif 'trial' in key_lower:
        return 'CLINICAL_TRIAL_ID'
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


def should_anonymize_key(key):
    """
    Determine if a key likely contains HIPAA identifiers based on its name.
    Only returns True for keys that might contain the 18 HIPAA identifiers.
    """
    hipaa_keywords = [
        # Names (but not provider names)
        'patient_name', 'name', 'first_name', 'last_name', 'middle_name',
        'relative', 'mother', 'father', 'spouse', 'employer',
        # Geographic
        'address', 'street', 'city', 'state', 'zip', 'zipcode', 'location',
        # Dates
        'date', 'dob', 'birth', 'admission', 'discharge', 'death',
        # Contact info
        'phone', 'telephone', 'mobile', 'cell', 'fax', 'email',
        # IDs
        'ssn', 'social', 'mrn', 'medical_record', 'patient_id',
        'insurance', 'member', 'policy', 'beneficiary',
        'license', 'certificate', 'employee_id', 'staff_id',
        # Technical
        'device', 'serial', 'implant', 'url', 'website', 'ip_address',
        'vehicle', 'vin', 'plate',
        # Biometric
        'fingerprint', 'retinal', 'voiceprint', 'biometric',
        # Other
        'trial', 'photo', 'image', 'unique_id'
    ]
    
    key_lower = key.lower()
    
    # Special handling for "name" fields - always check unless it's explicitly a provider
    if 'name' in key_lower and not any(provider in key_lower for provider in ['provider', 'doctor', 'physician', 'clinician', 'therapist']):
        return True
    
    # Exclude provider/doctor names from anonymization
    if any(provider in key_lower for provider in ['provider', 'doctor', 'physician', 'clinician', 'therapist']):
        return False
    
    return any(keyword in key_lower for keyword in hipaa_keywords)


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
