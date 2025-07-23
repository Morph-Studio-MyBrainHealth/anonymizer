"""
Enhanced PII/PHI Detection and Anonymization Module
Supports both standard PII and medical-specific data types
Modified to use non-medical replacements for medical entities
"""

import re
import random
import string
import json
import hashlib
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


def generate_non_medical_replacement(entity_type: str, original_value: str) -> str:
    """
    Generate non-medical replacement data for medical entities.
    Uses hash for consistent replacements.
    """
    # Use hash of original value to get consistent fake data
    hash_val = int(hashlib.md5(original_value.encode()).hexdigest()[:8], 16)
    
    non_medical_replacements = {
        'DIAGNOSIS': [
            'Blue Mountain Project',
            'Sunrise Initiative',
            'Green Valley Protocol',
            'Ocean Wave Study',
            'Silver Bridge Program',
            'Golden Gate Analysis',
            'Crystal River Method',
            'Desert Sand Framework',
            'Northern Light Process',
            'Eastern Shore Approach',
            'Maple Leaf System',
            'Thunder Bay Model',
            'Moonlight Strategy',
            'Starlight Pattern',
            'Rainbow Arc Design'
        ],
        'ORGANIZATION': [
            'Alpine Resources Center',
            'Riverside Associates',
            'Oakwood Services',
            'Pinehurst Group',
            'Lakeside Institute',
            'Mountain View Partners',
            'Valley Stream Corp',
            'Oceanside Enterprises',
            'Hillcrest Solutions',
            'Meadowbrook Systems',
            'Northwind Analytics',
            'Southgate Dynamics',
            'Eastside Innovations',
            'Westfield Operations',
            'Central Park Agency'
        ],
        'MEDICATION': [
            'Product Code A1B2',
            'Item Number C3D4',
            'Reference ID E5F6',
            'Catalog Entry G7H8',
            'Stock Code I9J0',
            'Asset Tag K1L2',
            'Inventory ID M3N4',
            'Serial Code O5P6',
            'Batch Number Q7R8',
            'Lot Reference S9T0'
        ],
        'MRN': [
            'REF-100234',
            'ID-200567',
            'NUM-300890',
            'CODE-401234',
            'TAG-502345',
            'KEY-603456',
            'SER-704567',
            'DOC-805678',
            'REC-906789',
            'FILE-007890'
        ],
        'PROVIDER_ID': [
            '1000000001',
            '2000000002',
            '3000000003',
            '4000000004',
            '5000000005',
            '6000000006',
            '7000000007',
            '8000000008',
            '9000000009',
            '1000000010'
        ],
        'INSURANCE_ID': [
            'POL123456789',
            'MEM234567890',
            'GRP345678901',
            'PLN456789012',
            'COV567890123',
            'BEN678901234',
            'SUB789012345',
            'ACC890123456',
            'REG901234567',
            'SVC012345678'
        ],
        'LAB_VALUE': [
            'Metric A: 42.7',
            'Index B: 3.14',
            'Score C: 98.6',
            'Value D: 7.25',
            'Reading E: 120',
            'Result F: 0.85',
            'Output G: 15.3',
            'Level H: 6.02',
            'Rate I: 72.0',
            'Factor J: 1.618'
        ],
        'PROCEDURE': [
            'Process 100-A',
            'Method 200-B',
            'Technique 300-C',
            'Protocol 400-D',
            'Operation 500-E',
            'Function 600-F',
            'Activity 700-G',
            'Task 800-H',
            'Action 900-I',
            'Step 1000-J'
        ],
        'MEDICAL_CONDITION': [
            'Factor X-12',
            'Element Y-34',
            'Component Z-56',
            'Variable W-78',
            'Parameter V-90',
            'Attribute U-21',
            'Property T-43',
            'Feature S-65',
            'Characteristic R-87',
            'Aspect Q-09'
        ],
        'CLINICAL_TRIAL_ID': [
            'TRIAL10000001',
            'STUDY20000002',
            'PROTO30000003',
            'RESRCH40000004',
            'TEST50000005',
            'EVAL60000006',
            'ASSESS70000007',
            'REVIEW80000008',
            'SURVEY90000009',
            'PROJECT00000010'
        ],
        'JOB_TITLE': [
            'Senior Analyst',
            'Project Coordinator',
            'Operations Manager',
            'Technical Lead',
            'Research Associate',
            'Quality Specialist',
            'Systems Administrator',
            'Program Director',
            'Data Architect',
            'Process Engineer',
            'Strategic Consultant',
            'Regional Supervisor',
            'Implementation Expert',
            'Solutions Designer',
            'Integration Specialist'
        ],
        'CLINICAL_NOTE': [
            'standard review completed',
            'routine evaluation performed',
            'scheduled assessment done',
            'periodic check finished',
            'regular inspection conducted',
            'systematic review executed',
            'comprehensive analysis completed',
            'detailed examination performed',
            'thorough investigation done',
            'methodical survey finished'
        ],
        'SLEEP_PATTERN': [
            'Pattern Alpha-7',
            'Sequence Beta-3',
            'Rhythm Gamma-1',
            'Cycle Delta-9',
            'Phase Epsilon-4',
            'Mode Zeta-2',
            'State Eta-8',
            'Form Theta-5',
            'Type Iota-6',
            'Configuration Kappa-0'
        ],
        'PSYCHIATRIC_SYMPTOM': [
            'Status Green-Active',
            'Condition Blue-Stable',
            'State Yellow-Monitored',
            'Phase Orange-Tracked',
            'Level Purple-Observed',
            'Mode Teal-Recorded',
            'Type Silver-Noted',
            'Form Gold-Documented',
            'Pattern Bronze-Logged',
            'Configuration Gray-Filed'
        ],
        'DAILY_ACTIVITY': [
            'Process Type A1',
            'Method Category B2',
            'Approach Level C3',
            'System Grade D4',
            'Protocol Class E5',
            'Procedure Rank F6',
            'Operation Tier G7',
            'Function Stage H8',
            'Activity Phase I9',
            'Task Mode J0'
        ],
        'NEUROPSYCH_SCORE': [
            '1', '2', '3', '4', '5', '6', '7', '8', '9', '10'
        ],
        'CAREGIVER_SCORE': [
            '1', '2', '3', '4', '5'
        ],
        'FAMILY_HISTORY': [
            'experienced a health event in their 70s',
            'had a medical condition in their 80s',
            'developed symptoms in their 90s',
            'showed changes in their senior years',
            'had health concerns in later life',
            'experienced age-related changes',
            'developed a condition over time',
            'showed progressive symptoms',
            'had multiple health factors',
            'experienced combined conditions'
        ],
        'OCCUPATION': [
            'professional services',
            'administrative role',
            'management position',
            'technical specialist',
            'advisory capacity',
            'operational duties',
            'strategic planning',
            'service delivery',
            'project coordination',
            'organizational leadership'
        ],
        'CLINICAL_OBSERVATION': [
            'standard findings noted',
            'typical presentation observed',
            'expected parameters recorded',
            'routine assessment completed',
            'normal range detected',
            'baseline characteristics present',
            'standard markers identified',
            'regular patterns observed',
            'consistent findings documented',
            'expected variations noted'
        ],
        'MEDICAL_PROCEDURE': [
            'standard evaluation discussed',
            'routine assessment considered',
            'optional testing reviewed',
            'voluntary participation offered',
            'research opportunity presented',
            'diagnostic option explained',
            'elective procedure mentioned',
            'screening method discussed',
            'investigative approach considered',
            'clinical protocol reviewed'
        ],
        'DURATION': [
            'several years',
            'extended period',
            'considerable time',
            'lengthy duration',
            'sustained timeframe',
            'prolonged interval',
            'significant span',
            'substantial period',
            'continuous duration',
            'ongoing timeframe'
        ],
        'CAREGIVING_HISTORY': [
            'provided family support',
            'assisted with care needs',
            'helped family member',
            'supported relative',
            'gave personal assistance',
            'offered family care',
            'provided home support',
            'assisted with daily needs',
            'helped with personal care',
            'supported family situation'
        ]
    }
    
    if entity_type in non_medical_replacements:
        options = non_medical_replacements[entity_type]
        return options[hash_val % len(options)]
    else:
        return f"REF-{entity_type[:3]}-{hash_val % 10000:04d}"


def generate_fake_data(entity_type: str) -> Tuple[str, str]:
    """
    Generate fake data based on entity type.
    Returns tuple of (generator_name, fake_value)
    Modified to use non-medical replacements for medical entities.
    """
    # Standard PII types - keep using Faker for these
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
    elif entity_type == 'DOB':
        # Generate a date of birth between 18 and 90 years ago
        days_ago = random.randint(18*365, 90*365)
        dob = datetime.now() - timedelta(days=days_ago)
        return 'faker', dob.strftime('%m/%d/%Y')
    
    # Medical-specific types - use non-medical replacements
    elif entity_type in ['DIAGNOSIS', 'ORGANIZATION', 'MEDICATION', 'MRN', 'PROVIDER_ID',
                        'INSURANCE_ID', 'LAB_VALUE', 'PROCEDURE', 'MEDICAL_CONDITION',
                        'CLINICAL_TRIAL_ID', 'JOB_TITLE', 'CLINICAL_NOTE', 'SLEEP_PATTERN',
                        'PSYCHIATRIC_SYMPTOM', 'DAILY_ACTIVITY', 'NEUROPSYCH_SCORE',
                        'CAREGIVER_SCORE', 'FAMILY_HISTORY', 'OCCUPATION',
                        'CLINICAL_OBSERVATION', 'MEDICAL_PROCEDURE', 'DURATION',
                        'CAREGIVING_HISTORY']:
        # Generate a random value to use as seed for consistent replacements
        random_value = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
        return 'non_medical_faker', generate_non_medical_replacement(entity_type, random_value)
    
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
            # For medical entities, use non-medical replacements
            if entity['Type'] in ['DIAGNOSIS', 'ORGANIZATION', 'MEDICATION', 'MRN', 
                                 'PROVIDER_ID', 'INSURANCE_ID', 'LAB_VALUE', 'PROCEDURE',
                                 'MEDICAL_CONDITION', 'CLINICAL_TRIAL_ID', 'NEUROPSYCH_SCORE',
                                 'CAREGIVER_SCORE', 'FAMILY_HISTORY', 'OCCUPATION',
                                 'CLINICAL_OBSERVATION', 'MEDICAL_PROCEDURE', 'DURATION',
                                 'CAREGIVING_HISTORY']:
                generator_name = 'non_medical_faker'
                fake_data = generate_non_medical_replacement(entity['Type'], entity['originalData'])
            else:
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
