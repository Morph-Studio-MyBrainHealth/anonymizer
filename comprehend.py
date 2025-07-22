"""
Enhanced PII/PHI Detection and Anonymization Module
Supports both standard PII and medical-specific data types
"""

import re
import random
import string
import json
from typing import List, Dict, Tuple, Any
from faker import Faker
import boto3
from datetime import datetime, timedelta

# Initialize Faker for generating fake data
fake = Faker()

# Initialize AWS Comprehend client (if using AWS)
try:
    comprehend_client = boto3.client('comprehend', region_name='us-east-1')
except:
    comprehend_client = None
    print("AWS Comprehend not available, using local detection only")


def detect_pii_data(text: str) -> List[Dict[str, Any]]:
    """
    Enhanced PII detection including medical entities.
    Combines AWS Comprehend (if available) with custom medical detection.
    """
    entities = []
    
    # Try AWS Comprehend first if available
    if comprehend_client:
        try:
            response = comprehend_client.detect_pii_entities(
                Text=text,
                LanguageCode='en'
            )
            
            # Convert AWS response to our format
            for entity in response.get('Entities', []):
                entities.append({
                    'Type': entity['Type'],
                    'originalData': text[entity['BeginOffset']:entity['EndOffset']],
                    'BeginOffset': entity['BeginOffset'],
                    'EndOffset': entity['EndOffset'],
                    'Score': entity['Score']
                })
        except Exception as e:
            print(f"AWS Comprehend error: {e}, falling back to local detection")
    
    # Always run local detection for patterns AWS might miss
    local_entities = detect_local_pii(text)
    medical_entities = detect_medical_entities(text)
    
    # Combine all entities
    all_entities = entities + local_entities + medical_entities
    
    # Remove duplicates and overlapping entities
    cleaned_entities = remove_overlapping_entities(all_entities)
    
    return cleaned_entities


def detect_local_pii(text: str) -> List[Dict[str, Any]]:
    """
    Local PII detection using regex patterns.
    """
    entities = []
    
    # Email pattern
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    for match in re.finditer(email_pattern, text):
        entities.append({
            'Type': 'EMAIL',
            'originalData': match.group(),
            'BeginOffset': match.start(),
            'EndOffset': match.end(),
            'Score': 0.99
        })
    
    # Phone number patterns
    phone_patterns = [
        r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',  # US phone
        r'\b\(\d{3}\)\s*\d{3}[-.]?\d{4}\b',  # US phone with parentheses
        r'\b\+?1?\s*\(?(\d{3})\)?[-.\s]?(\d{3})[-.\s]?(\d{4})\b'  # Various formats
    ]
    for pattern in phone_patterns:
        for match in re.finditer(pattern, text):
            entities.append({
                'Type': 'PHONE_NUMBER',
                'originalData': match.group(),
                'BeginOffset': match.start(),
                'EndOffset': match.end(),
                'Score': 0.95
            })
    
    # SSN pattern
    ssn_pattern = r'\b\d{3}-\d{2}-\d{4}\b'
    for match in re.finditer(ssn_pattern, text):
        entities.append({
            'Type': 'SSN',
            'originalData': match.group(),
            'BeginOffset': match.start(),
            'EndOffset': match.end(),
            'Score': 0.98
            })
    
    # Date patterns
    date_patterns = [
        r'\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b',  # MM/DD/YYYY or MM-DD-YYYY
        r'\b\d{2,4}[/-]\d{1,2}[/-]\d{1,2}\b',  # YYYY/MM/DD
        r'\b\d{1,2}\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{2,4}\b',  # DD Month YYYY
        r'\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},?\s+\d{2,4}\b'  # Month DD, YYYY
    ]
    for pattern in date_patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            entities.append({
                'Type': 'DATE',
                'originalData': match.group(),
                'BeginOffset': match.start(),
                'EndOffset': match.end(),
                'Score': 0.9
            })
    
    # Credit card pattern (simplified)
    cc_pattern = r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'
    for match in re.finditer(cc_pattern, text):
        entities.append({
            'Type': 'CREDIT_DEBIT_NUMBER',
            'originalData': match.group(),
            'BeginOffset': match.start(),
            'EndOffset': match.end(),
            'Score': 0.95
        })
    
    # ZIP code pattern
    zip_pattern = r'\b\d{5}(?:-\d{4})?\b'
    for match in re.finditer(zip_pattern, text):
        # Check if it's not part of a longer number
        if match.start() == 0 or not text[match.start()-1].isdigit():
            if match.end() == len(text) or not text[match.end()].isdigit():
                entities.append({
                    'Type': 'ZIP',
                    'originalData': match.group(),
                    'BeginOffset': match.start(),
                    'EndOffset': match.end(),
                    'Score': 0.85
                })
    
    return entities


def detect_medical_entities(text: str) -> List[Dict[str, Any]]:
    """
    Detect medical-specific entities in text.
    """
    entities = []
    
    # ICD codes (like F06.7, E11.9, I10)
    icd_pattern = r'\b[A-TV-Z][0-9][0-9AB]\.?[0-9]{0,4}\b'
    for match in re.finditer(icd_pattern, text):
        # Check context to confirm it's likely a diagnosis code
        context_before = text[max(0, match.start()-30):match.start()].lower()
        context_after = text[match.end():min(len(text), match.end()+30)].lower()
        
        if any(word in context_before + context_after for word in ['diagnosis', 'icd', 'code', 'condition']):
            score = 0.95
        else:
            score = 0.8
            
        entities.append({
            'Type': 'DIAGNOSIS',
            'originalData': match.group(),
            'BeginOffset': match.start(),
            'EndOffset': match.end(),
            'Score': score
        })
    
    # MRN patterns
    mrn_patterns = [
        r'\b(?:MRN|mrn|Medical Record Number)[\s:#-]*([A-Z0-9-]+)\b',
        r'\b(?:Patient ID|patient id)[\s:#-]*([A-Z0-9-]+)\b',
        r'\b[A-Z]{2,4}-\d{6,10}\b'  # Common MRN format
    ]
    for pattern in mrn_patterns:
        for match in re.finditer(pattern, text):
            entities.append({
                'Type': 'MRN',
                'originalData': match.group(),
                'BeginOffset': match.start(),
                'EndOffset': match.end(),
                'Score': 0.95
            })
    
    # Medication patterns (drug name + dosage)
    med_pattern = r'\b[A-Z][a-z]+(?:in|ol|ide|ate|ine|one)?\s+\d+\s*(?:mg|mcg|g|ml|mL|units?|IU)\b'
    for match in re.finditer(med_pattern, text):
        entities.append({
            'Type': 'MEDICATION',
            'originalData': match.group(),
            'BeginOffset': match.start(),
            'EndOffset': match.end(),
            'Score': 0.85
        })
    
    # Lab values with units
    lab_patterns = [
        r'\b\d+\.?\d*\s*(?:mg/dL|mmol/L|mEq/L|g/dL|%|mmHg|°F|°C)\b',
        r'\b(?:A1C|HbA1c|Hemoglobin A1c)[\s:]+\d+\.?\d*\s*%?\b',
        r'\b(?:Glucose|Creatinine|Cholesterol)[\s:]+\d+\.?\d*\s*(?:mg/dL)?\b'
    ]
    for pattern in lab_patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            entities.append({
                'Type': 'LAB_VALUE',
                'originalData': match.group(),
                'BeginOffset': match.start(),
                'EndOffset': match.end(),
                'Score': 0.85
            })
    
    # Provider/Doctor names (Dr. FirstName LastName pattern)
    provider_pattern = r'\b(?:Dr\.?|Doctor|Physician)\s+[A-Z][a-z]+\s+[A-Z][a-z]+\b'
    for match in re.finditer(provider_pattern, text):
        entities.append({
            'Type': 'NAME',
            'originalData': match.group(),
            'BeginOffset': match.start(),
            'EndOffset': match.end(),
            'Score': 0.9
        })
    
    # NPI (National Provider Identifier) - 10 digits
    npi_pattern = r'\b(?:NPI|npi)[\s:#-]*(\d{10})\b'
    for match in re.finditer(npi_pattern, text):
        entities.append({
            'Type': 'PROVIDER_ID',
            'originalData': match.group(),
            'BeginOffset': match.start(),
            'EndOffset': match.end(),
            'Score': 0.95
        })
    
    # Insurance ID patterns
    insurance_pattern = r'\b[A-Z]{1,3}\d{6,12}\b'
    for match in re.finditer(insurance_pattern, text):
        # Check context
        context = text[max(0, match.start()-20):min(len(text), match.end()+20)].lower()
        if any(word in context for word in ['insurance', 'member', 'policy', 'id']):
            entities.append({
                'Type': 'INSURANCE_ID',
                'originalData': match.group(),
                'BeginOffset': match.start(),
                'EndOffset': match.end(),
                'Score': 0.85
            })
    
    # Clinical trial identifiers
    trial_pattern = r'\bNCT\d{8}\b'
    for match in re.finditer(trial_pattern, text):
        entities.append({
            'Type': 'CLINICAL_TRIAL_ID',
            'originalData': match.group(),
            'BeginOffset': match.start(),
            'EndOffset': match.end(),
            'Score': 0.95
        })
    
    return entities


def remove_overlapping_entities(entities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Remove overlapping entities, keeping the one with higher score.
    """
    if not entities:
        return []
    
    # Sort by score descending, then by length descending
    sorted_entities = sorted(entities, 
                           key=lambda x: (x['Score'], x['EndOffset'] - x['BeginOffset']), 
                           reverse=True)
    
    cleaned = []
    for entity in sorted_entities:
        overlap = False
        for existing in cleaned:
            # Check if entities overlap
            if (entity['BeginOffset'] < existing['EndOffset'] and 
                entity['EndOffset'] > existing['BeginOffset']):
                overlap = True
                break
        if not overlap:
            cleaned.append(entity)
    
    # Sort by position for consistent output
    cleaned.sort(key=lambda x: x['BeginOffset'])
    return cleaned


def generate_fake_data(entity_type: str) -> Tuple[str, str]:
    """
    Generate fake data based on entity type.
    Returns tuple of (generator_name, fake_value)
    """
    # Standard PII types
    if entity_type == 'NAME':
        return 'faker', fake.name()
    elif entity_type == 'ADDRESS':
        return 'faker', fake.address().replace('\n', ' ')
    elif entity_type == 'PHONE_NUMBER':
        return 'faker', fake.phone_number()
    elif entity_type == 'EMAIL':
        return 'faker', fake.email()
    elif entity_type == 'SSN':
        return 'faker', fake.ssn()
    elif entity_type == 'DATE':
        return 'faker', fake.date()
    elif entity_type == 'CREDIT_DEBIT_NUMBER':
        return 'faker', fake.credit_card_number()
    elif entity_type == 'ZIP':
        return 'faker', fake.zipcode()
    elif entity_type == 'URL':
        return 'faker', fake.url()
    elif entity_type == 'IP_ADDRESS':
        return 'faker', fake.ipv4()
    elif entity_type == 'MAC_ADDRESS':
        return 'faker', fake.mac_address()
    elif entity_type == 'LICENSE_PLATE':
        return 'faker', fake.license_plate()
    elif entity_type == 'BANK_ACCOUNT':
        return 'faker', fake.iban()
    
    # Medical-specific types
    elif entity_type == 'DIAGNOSIS':
        diagnoses = [
            'Essential Hypertension (I10)',
            'Type 2 Diabetes Mellitus (E11.9)',
            'Major Depressive Disorder (F32.9)',
            'Generalized Anxiety Disorder (F41.1)',
            'Chronic Obstructive Pulmonary Disease (J44.0)',
            'Coronary Artery Disease (I25.10)',
            'Atrial Fibrillation (I48.91)',
            'Hypothyroidism (E03.9)',
            'Osteoarthritis (M19.90)',
            'Gastroesophageal Reflux Disease (K21.9)',
            'Hyperlipidemia (E78.5)',
            'Asthma (J45.909)',
            'Chronic Kidney Disease (N18.3)',
            'Heart Failure (I50.9)',
            'Migraine (G43.909)'
        ]
        return 'medical_faker', random.choice(diagnoses)
    
    elif entity_type == 'ORGANIZATION':
        prefixes = ['Regional', 'Community', 'Metropolitan', 'Central', 'Premier', 
                   'Advanced', 'Comprehensive', 'Integrated', 'Unity', 'Memorial']
        types = ['Medical Center', 'Health Clinic', 'Hospital', 'Healthcare System', 
                'Medical Group', 'Health Services', 'Care Center', 'Wellness Center']
        return 'medical_faker', f"{random.choice(prefixes)} {random.choice(types)}"
    
    elif entity_type == 'MEDICATION':
        medications = [
            'Lisinopril 10mg',
            'Metformin 500mg',
            'Amlodipine 5mg',
            'Atorvastatin 20mg',
            'Omeprazole 20mg',
            'Levothyroxine 50mcg',
            'Metoprolol 25mg',
            'Sertraline 50mg',
            'Gabapentin 300mg',
            'Losartan 50mg',
            'Albuterol 90mcg',
            'Fluoxetine 20mg',
            'Pravastatin 40mg',
            'Furosemide 40mg',
            'Hydrochlorothiazide 25mg'
        ]
        return 'medical_faker', random.choice(medications)
    
    elif entity_type == 'MRN':
        # Medical Record Number
        prefix = random.choice(['MRN', 'MR', 'PT'])
        number = random.randint(100000, 9999999)
        return 'medical_faker', f"{prefix}-{number}"
    
    elif entity_type == 'PROVIDER_ID':
        # NPI number format (10 digits)
        return 'medical_faker', f"{random.randint(1000000000, 9999999999)}"
    
    elif entity_type == 'INSURANCE_ID':
        letters = ''.join(random.choices(string.ascii_uppercase, k=3))
        numbers = ''.join(random.choices(string.digits, k=9))
        return 'medical_faker', f"{letters}{numbers}"
    
    elif entity_type == 'LAB_VALUE':
        values = [
            '120 mg/dL',
            '7.2%',
            '98.6°F',
            '120/80 mmHg',
            'Normal Range',
            'Within Limits',
            '5.5 mmol/L',
            '140 mEq/L',
            '4.5 g/dL',
            '1.2 mg/dL'
        ]
        return 'medical_faker', random.choice(values)
    
    elif entity_type == 'PROCEDURE':
        procedures = [
            'Physical Examination',
            'Laboratory Studies',
            'Chest X-Ray',
            'Electrocardiogram',
            'Echocardiogram',
            'CT Scan',
            'MRI Brain',
            'Colonoscopy',
            'Upper Endoscopy',
            'Pulmonary Function Test',
            'Stress Test',
            'Ultrasound Abdomen'
        ]
        return 'medical_faker', random.choice(procedures)
    
    elif entity_type == 'MEDICAL_CONDITION':
        conditions = [
            'Hypertension',
            'Diabetes',
            'Asthma',
            'Arthritis',
            'Depression',
            'Anxiety',
            'GERD',
            'Allergies',
            'Migraine',
            'COPD',
            'Hypothyroidism',
            'Anemia'
        ]
        return 'medical_faker', random.choice(conditions)
    
    elif entity_type == 'CLINICAL_TRIAL_ID':
        return 'medical_faker', f"NCT{random.randint(10000000, 99999999)}"
    
    elif entity_type == 'DOB':
        # Generate a date of birth between 18 and 90 years ago
        days_ago = random.randint(18*365, 90*365)
        dob = datetime.now() - timedelta(days=days_ago)
        return 'faker', dob.strftime('%m/%d/%Y')
    
    elif entity_type == 'JOB_TITLE':
        titles = [
            'Consultant Physician',
            'Senior Specialist',
            'Clinical Director',
            'Medical Officer',
            'Research Coordinator',
            'Clinical Assistant',
            'Healthcare Professional',
            'Medical Consultant',
            'Senior Clinician',
            'Clinical Specialist',
            'Nurse Practitioner',
            'Physician Assistant',
            'Research Assistant',
            'Clinical Research Coordinator'
        ]
        return 'medical_faker', random.choice(titles)
    
    elif entity_type == 'CLINICAL_NOTE':
        notes = [
            'routine follow-up and assessment',
            'standard clinical evaluation',
            'comprehensive health review',
            'periodic medical assessment',
            'general health consultation',
            'clinical review and planning',
            'medical evaluation and care planning',
            'health status assessment',
            'diagnostic workup and evaluation',
            'treatment planning and review'
        ]
        return 'medical_faker', random.choice(notes)
    
    # Generic fallback
    else:
        return 'generic', f"[REDACTED-{entity_type}]"


def generate_fake_entities(masterid: str, entities: List[Dict], existing_records: List[Dict]) -> List[Dict]:
    """
    Generate fake data for detected entities, checking existing records first.
    """
    new_records = []
    
    for entity in entities:
        # Check if we already have fake data for this entity
        fake_data = None
        for record in existing_records:
            if (record['piiType'].upper() == entity['Type'].upper() and 
                record['originalData'].upper() == entity['originalData'].upper()):
                fake_data = record['fakeData']
                break
        
        # Check in new records too
        if not fake_data:
            for record in new_records:
                if (record['piiType'].upper() == entity['Type'].upper() and 
                    record['originalData'].upper() == entity['originalData'].upper()):
                    fake_data = record['fakeData']
                    break
        
        # Generate new fake data if needed
        if not fake_data:
            generator_name, fake_data = generate_fake_data(entity['Type'])
            new_records.append({
                'uuid': masterid,
                'piiType': entity['Type'],
                'originalData': entity['originalData'],
                'fakeDataType': generator_name,
                'fakeData': fake_data
            })
    
    return new_records


def anonymize(text: str, entities: List[Dict]) -> str:
    """
    Replace detected entities with fake data in text.
    """
    if not entities:
        return text
    
    # Sort entities by position (reverse order to maintain offsets)
    sorted_entities = sorted(entities, key=lambda x: x['BeginOffset'], reverse=True)
    
    anonymized_text = text
    for entity in sorted_entities:
        # Get the fake data for this entity
        fake_data = entity.get('fakeData', f"[REDACTED-{entity['Type']}]")
        
        # Replace the original data with fake data
        start = entity['BeginOffset']
        end = entity['EndOffset']
        anonymized_text = anonymized_text[:start] + fake_data + anonymized_text[end:]
    
    return anonymized_text


def de_anonymize(text: str, pii_records: List[Dict]) -> str:
    """
    Replace fake data with original PII in text.
    """
    if not pii_records:
        return text
    
    de_anonymized_text = text
    
    # Sort by length of fake data (descending) to avoid partial replacements
    sorted_records = sorted(pii_records, key=lambda x: len(x['fakeData']), reverse=True)
    
    for record in sorted_records:
        fake_data = record['fakeData']
        original_data = record['originalData']
        
        # Replace all occurrences of fake data with original
        de_anonymized_text = de_anonymized_text.replace(fake_data, original_data)
    
    return de_anonymized_text


# Utility functions for testing
def test_detection():
    """Test PII/PHI detection with sample text."""
    test_text = """
    Patient: John Smith, DOB: 03/15/1975, MRN: ABC-123456
    Phone: 555-123-4567, Email: jsmith@email.com
    Diagnosis: Type 2 Diabetes (E11.9)
    Medications: Metformin 1000mg BID, Lisinopril 10mg daily
    Provider: Dr. Jane Johnson, NPI: 1234567890
    Insurance ID: XYZ123456789
    Next appointment: 04/20/2025 at 2:30 PM
    """
    
    entities = detect_pii_data(test_text)
    print(f"Detected {len(entities)} entities:")
    for entity in entities:
        print(f"  {entity['Type']}: {entity['originalData']}")
    
    return entities


if __name__ == "__main__":
    # Run test if executed directly
    test_detection()
