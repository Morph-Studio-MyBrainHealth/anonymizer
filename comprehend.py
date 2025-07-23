"""
Enhanced PII/PHI Detection and Anonymization Module
Supports HIPAA Safe Harbor 18 identifiers ONLY
Medical information is preserved for healthcare use
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
    HIPAA-compliant PII detection.
    Only detects the 18 HIPAA Safe Harbor identifiers.
    Does NOT detect medical/diagnostic information.
    """
    entities = []
    
    # Try AWS Comprehend first if available
    if comprehend_client:
        try:
            response = comprehend_client.detect_pii_entities(
                Text=text,
                LanguageCode='en'
            )
            
            # Convert AWS response to our format - filter out medical entities
            for entity in response.get('Entities', []):
                # Only include true PII, not medical information
                if entity['Type'] not in ['DIAGNOSIS', 'MEDICATION', 'MEDICAL_CONDITION']:
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
    
    # Combine all entities
    all_entities = entities + local_entities
    
    # Remove duplicates and overlapping entities
    cleaned_entities = remove_overlapping_entities(all_entities)
    
    return cleaned_entities


def detect_local_pii(text: str) -> List[Dict[str, Any]]:
    """
    Local PII detection using regex patterns.
    Only detects HIPAA Safe Harbor identifiers.
    """
    entities = []
    
    # HIPAA Identifier 1: Names (but NOT healthcare provider names)
    # First, let's identify healthcare provider names to exclude them
    provider_titles = r'\b(?:Dr\.?|Doctor|MD|RN|NP|PA|Nurse|Physician|Therapist|Psychiatrist|Psychologist|Counselor)\b'
    provider_pattern = rf'{provider_titles}\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*'
    provider_matches = list(re.finditer(provider_pattern, text))
    provider_spans = [(m.start(), m.end()) for m in provider_matches]
    
    # Name patterns - Enhanced to catch more name formats
    name_patterns = [
        # Name: pattern at start of line
        (r'Name:\s*([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+)*)', False),
        # Patient: pattern
        (r'Patient:\s*([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+)*)', False),
        # Names with titles - capture the whole thing including title
        (r'\b((?:Mr\.?|Mrs\.?|Ms\.?|Miss)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\b', False),
        # Relative patterns
        (r'\b(?:mother|father|sister|brother|spouse|wife|husband|son|daughter|parent)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)', True),
        # General name pattern (First Last) - in specific contexts
        (r'\b([A-Z][a-z]+\s+[A-Z][a-z]+)(?=\s*(?:DOB|Phone|Address|,|\n|$|works|lives|employed|called|contacted|visited))', False),
        # Single capitalized names in conversation context
        (r'(?:Hello|Hi|Dear|Hey)\s+([A-Z][a-z]+)', True),
        # Standalone last names after titles without first names
        (r'(?:Mr\.?|Mrs\.?|Ms\.?|Miss)\s+([A-Z][a-z]+)(?:\s|,|\.)', False),
        # Names in quotes or after certain verbs
        (r'(?:called|named|contacted)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)', True),
        # Standalone capitalized words that could be names in specific contexts
        (r'(?:^|\.\s+)([A-Z][a-z]+)(?:\s*[:,]|\s+(?:how|are|is|was|has|had|will|would|can|could|should))', False),
        # Simple First Last pattern for JSON/isolated contexts (must be exactly two capitalized words)
        (r'^([A-Z][a-z]+\s+[A-Z][a-z]+)$', False),
    ]
    
    # Common medical/non-name terms to exclude
    medical_terms = [
        'Type', 'Diabetes', 'Hypertension', 'Blood', 'Pressure', 'Heart', 'Rate',
        'Glucose', 'Insulin', 'Metformin', 'Lisinopril', 'Daily', 'Twice',
        'Morning', 'Evening', 'January', 'February', 'March', 'April', 'May', 'June',
        'July', 'August', 'September', 'October', 'November', 'December',
        'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday',
        'North', 'South', 'East', 'West', 'Central', 'General', 'Hospital',
        'Clinic', 'Center', 'Medical', 'Health', 'Care', 'Service', 'Department',
        'Emergency', 'Primary', 'Secondary', 'Tertiary', 'Internal', 'Family',
        'Physical', 'Mental', 'Behavioral', 'Cognitive', 'Memory', 'Sleep',
        'Pain', 'Chronic', 'Acute', 'Severe', 'Moderate', 'Mild', 'Normal',
        'Abnormal', 'Positive', 'Negative', 'Stable', 'Critical', 'Fair', 'Good',
        'Poor', 'Excellent', 'Test', 'Result', 'Lab', 'Report', 'Study',
        'Clinical', 'Trial', 'Research', 'Protocol', 'Standard', 'Guideline'
    ]
    
    for pattern in name_patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            name_start = match.start(1)
            name_end = match.end(1)
            
            # Check if this name is a healthcare provider
            is_provider = any(name_start >= ps and name_end <= pe for ps, pe in provider_spans)
            
            if not is_provider:
                name = match.group(1)
                entities.append({
                    'Type': 'NAME',
                    'originalData': name,
                    'BeginOffset': name_start,
                    'EndOffset': name_end,
                    'Score': 0.95
                })
    
    # HIPAA Identifier 3: Email addresses
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    for match in re.finditer(email_pattern, text):
        entities.append({
            'Type': 'EMAIL',
            'originalData': match.group(),
            'BeginOffset': match.start(),
            'EndOffset': match.end(),
            'Score': 0.99
        })
    
    # HIPAA Identifier 4: Phone numbers
    phone_patterns = [
        r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
        r'\b\(\d{3}\)\s*\d{3}[-.]?\d{4}\b',
        r'\b\+?1?\s*\(?(\d{3})\)?[-.\s]?(\d{3})[-.\s]?(\d{4})\b'
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
    
    # HIPAA Identifier 5: Fax numbers (same as phone pattern)
    # Already covered by phone patterns above
    
    # HIPAA Identifier 7: Social Security Numbers
    ssn_pattern = r'\b\d{3}-\d{2}-\d{4}\b'
    for match in re.finditer(ssn_pattern, text):
        entities.append({
            'Type': 'SSN',
            'originalData': match.group(),
            'BeginOffset': match.start(),
            'EndOffset': match.end(),
            'Score': 0.98
        })
    
    # HIPAA Identifier 3: Dates (except year)
    date_patterns = [
        r'\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b',
        r'\b\d{2,4}[/-]\d{1,2}[/-]\d{1,2}\b',
        r'\b\d{1,2}\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{2,4}\b',
        r'\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},?\s+\d{2,4}\b'
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
    
    # HIPAA Identifier 10: Account numbers (credit cards)
    cc_pattern = r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'
    for match in re.finditer(cc_pattern, text):
        entities.append({
            'Type': 'CREDIT_DEBIT_NUMBER',
            'originalData': match.group(),
            'BeginOffset': match.start(),
            'EndOffset': match.end(),
            'Score': 0.95
        })
    
    # HIPAA Identifier 2: Geographic subdivisions - ZIP codes
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
    
    # HIPAA Identifier 2: Geographic subdivisions - Addresses
    address_pattern = r'\b\d+\s+[A-Za-z\s]+(?:St|Street|Ave|Avenue|Rd|Road|Dr|Drive|Ln|Lane|Blvd|Boulevard|Way|Court|Ct|Plaza|Place|Pl)\.?\s*,?\s*[A-Za-z\s]+,?\s*[A-Z]{2}\s+\d{5}(?:-\d{4})?'
    for match in re.finditer(address_pattern, text):
        entities.append({
            'Type': 'ADDRESS',
            'originalData': match.group(),
            'BeginOffset': match.start(),
            'EndOffset': match.end(),
            'Score': 0.9
        })
    
    # HIPAA Identifier 8: Medical Record Numbers
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
    
    # HIPAA Identifier 9: Health plan beneficiary numbers
    insurance_patterns = [
        r'Insurance ID:\s*([A-Z0-9]+)',
        r'\b(?:Member ID|Policy Number)[\s:#-]*([A-Z0-9-]+)\b',
        r'\b[A-Z]{1,3}\d{6,12}\b'  # Common insurance ID format
    ]
    for pattern in insurance_patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            # For the first two patterns, use group 1
            if match.lastindex:
                entities.append({
                    'Type': 'INSURANCE_ID',
                    'originalData': match.group(1),
                    'BeginOffset': match.start(1),
                    'EndOffset': match.end(1),
                    'Score': 0.95
                })
            else:
                # Check context for the third pattern
                context = text[max(0, match.start()-20):min(len(text), match.end()+20)].lower()
                if any(word in context for word in ['insurance', 'member', 'policy', 'beneficiary']):
                    entities.append({
                        'Type': 'INSURANCE_ID',
                        'originalData': match.group(),
                        'BeginOffset': match.start(),
                        'EndOffset': match.end(),
                        'Score': 0.85
                    })
    
    # HIPAA Identifier 11: Certificate/License numbers
    license_pattern = r'\b(?:License|Certificate)[\s#:]*([A-Z0-9-]+)\b'
    for match in re.finditer(license_pattern, text, re.IGNORECASE):
        entities.append({
            'Type': 'LICENSE_NUMBER',
            'originalData': match.group(),
            'BeginOffset': match.start(),
            'EndOffset': match.end(),
            'Score': 0.9
        })
    
    # HIPAA Identifier 12: Vehicle identifiers
    vehicle_patterns = [
        r'\b(?:License Plate|Plate)[\s:#]*([A-Z0-9-]+)\b',
        r'\bVIN[\s:#]*([A-Z0-9]{17})\b'
    ]
    for pattern in vehicle_patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            entities.append({
                'Type': 'VEHICLE_ID',
                'originalData': match.group(),
                'BeginOffset': match.start(),
                'EndOffset': match.end(),
                'Score': 0.95
            })
    
    # HIPAA Identifier 13: Device identifiers and serial numbers
    device_patterns = [
        r'\b(?:Serial Number|Serial|SN)[\s:#]*([A-Z0-9-]+)\b',
        r'\b(?:Device ID|Device)[\s:#]*([A-Z0-9-]+)\b',
        r'\b(?:Pacemaker|Pump|Implant)\s+(?:ID|Serial)[\s:#]*([A-Z0-9-]+)\b'
    ]
    for pattern in device_patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            entities.append({
                'Type': 'DEVICE_ID',
                'originalData': match.group(),
                'BeginOffset': match.start(),
                'EndOffset': match.end(),
                'Score': 0.95
            })
    
    # HIPAA Identifier 14: URLs
    url_pattern = r'https?://[^\s]+'
    for match in re.finditer(url_pattern, text):
        entities.append({
            'Type': 'URL',
            'originalData': match.group(),
            'BeginOffset': match.start(),
            'EndOffset': match.end(),
            'Score': 0.99
        })
    
    # HIPAA Identifier 15: IP addresses
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    for match in re.finditer(ip_pattern, text):
        entities.append({
            'Type': 'IP_ADDRESS',
            'originalData': match.group(),
            'BeginOffset': match.start(),
            'EndOffset': match.end(),
            'Score': 0.95
        })
    
    # HIPAA Identifier 16: Biometric identifiers
    biometric_patterns = [
        r'\b(?:Fingerprint|Retinal|Voiceprint|Facial Recognition)[\s:]*(ID)?[\s:#]*([A-Z0-9-]+)\b'
    ]
    for pattern in biometric_patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            entities.append({
                'Type': 'BIOMETRIC_ID',
                'originalData': match.group(),
                'BeginOffset': match.start(),
                'EndOffset': match.end(),
                'Score': 0.95
            })
    
    # HIPAA Identifier 18: Any other unique identifying number
    # This includes clinical trial identifiers
    trial_pattern = r'\bNCT\d{8}\b'
    for match in re.finditer(trial_pattern, text):
        entities.append({
            'Type': 'CLINICAL_TRIAL_ID',
            'originalData': match.group(),
            'BeginOffset': match.start(),
            'EndOffset': match.end(),
            'Score': 0.95
        })
    
    # Employee IDs
    employee_pattern = r'\b(?:Employee ID|EID)[\s:#]*([A-Z0-9-]+)\b'
    for match in re.finditer(employee_pattern, text, re.IGNORECASE):
        entities.append({
            'Type': 'EMPLOYEE_ID',
            'originalData': match.group(),
            'BeginOffset': match.start(),
            'EndOffset': match.end(),
            'Score': 0.9
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
    Only handles HIPAA identifiers, not medical information.
    """
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
    elif entity_type == 'MRN':
        # Generate medical record number
        return 'faker', f"MRN-{fake.random_number(digits=8)}"
    elif entity_type == 'INSURANCE_ID':
        # Generate insurance ID
        prefix = random.choice(['POL', 'MEM', 'GRP'])
        return 'faker', f"{prefix}{fake.random_number(digits=9)}"
    elif entity_type == 'LICENSE_NUMBER':
        return 'faker', fake.license_plate()
    elif entity_type == 'VEHICLE_ID':
        # Generate VIN-like identifier
        return 'faker', ''.join(random.choices(string.ascii_uppercase + string.digits, k=17))
    elif entity_type == 'DEVICE_ID':
        # Generate device serial number
        return 'faker', f"SN-{fake.random_number(digits=10)}"
    elif entity_type == 'BIOMETRIC_ID':
        return 'faker', f"BIO-{fake.random_number(digits=12)}"
    elif entity_type == 'CLINICAL_TRIAL_ID':
        return 'faker', f"NCT{fake.random_number(digits=8)}"
    elif entity_type == 'EMPLOYEE_ID':
        return 'faker', f"EMP{fake.random_number(digits=6)}"
    elif entity_type == 'DOB':
        # Generate a date of birth between 18 and 90 years ago
        days_ago = random.randint(18*365, 90*365)
        dob = datetime.now() - timedelta(days=days_ago)
        return 'faker', dob.strftime('%m/%d/%Y')
    else:
        # Generic fallback for any other unique identifier
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
            
            # Store the fake data with the entity for later use
            entity['fakeData'] = fake_data
            
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
, False),
        # Three-part names (First Middle Last)
        (r'^([A-Z][a-z]+\s+[A-Z][a-z]+\s+[A-Z][a-z]+)
    
    # Common medical/non-name terms to exclude
    medical_terms = [
        'Type', 'Diabetes', 'Hypertension', 'Blood', 'Pressure', 'Heart', 'Rate',
        'Glucose', 'Insulin', 'Metformin', 'Lisinopril', 'Daily', 'Twice',
        'Morning', 'Evening', 'January', 'February', 'March', 'April', 'May', 'June',
        'July', 'August', 'September', 'October', 'November', 'December',
        'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday',
        'North', 'South', 'East', 'West', 'Central', 'General', 'Hospital',
        'Clinic', 'Center', 'Medical', 'Health', 'Care', 'Service', 'Department'
    ]
    
    for pattern in name_patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            name_start = match.start(1)
            name_end = match.end(1)
            
            # Check if this name is a healthcare provider
            is_provider = any(name_start >= ps and name_end <= pe for ps, pe in provider_spans)
            
            if not is_provider:
                name = match.group(1)
                entities.append({
                    'Type': 'NAME',
                    'originalData': name,
                    'BeginOffset': name_start,
                    'EndOffset': name_end,
                    'Score': 0.95
                })
    
    # HIPAA Identifier 3: Email addresses
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    for match in re.finditer(email_pattern, text):
        entities.append({
            'Type': 'EMAIL',
            'originalData': match.group(),
            'BeginOffset': match.start(),
            'EndOffset': match.end(),
            'Score': 0.99
        })
    
    # HIPAA Identifier 4: Phone numbers
    phone_patterns = [
        r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
        r'\b\(\d{3}\)\s*\d{3}[-.]?\d{4}\b',
        r'\b\+?1?\s*\(?(\d{3})\)?[-.\s]?(\d{3})[-.\s]?(\d{4})\b'
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
    
    # HIPAA Identifier 5: Fax numbers (same as phone pattern)
    # Already covered by phone patterns above
    
    # HIPAA Identifier 7: Social Security Numbers
    ssn_pattern = r'\b\d{3}-\d{2}-\d{4}\b'
    for match in re.finditer(ssn_pattern, text):
        entities.append({
            'Type': 'SSN',
            'originalData': match.group(),
            'BeginOffset': match.start(),
            'EndOffset': match.end(),
            'Score': 0.98
        })
    
    # HIPAA Identifier 3: Dates (except year)
    date_patterns = [
        r'\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b',
        r'\b\d{2,4}[/-]\d{1,2}[/-]\d{1,2}\b',
        r'\b\d{1,2}\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{2,4}\b',
        r'\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},?\s+\d{2,4}\b'
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
    
    # HIPAA Identifier 10: Account numbers (credit cards)
    cc_pattern = r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'
    for match in re.finditer(cc_pattern, text):
        entities.append({
            'Type': 'CREDIT_DEBIT_NUMBER',
            'originalData': match.group(),
            'BeginOffset': match.start(),
            'EndOffset': match.end(),
            'Score': 0.95
        })
    
    # HIPAA Identifier 2: Geographic subdivisions - ZIP codes
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
    
    # HIPAA Identifier 2: Geographic subdivisions - Addresses
    address_pattern = r'\b\d+\s+[A-Za-z\s]+(?:St|Street|Ave|Avenue|Rd|Road|Dr|Drive|Ln|Lane|Blvd|Boulevard|Way|Court|Ct|Plaza|Place|Pl)\.?\s*,?\s*[A-Za-z\s]+,?\s*[A-Z]{2}\s+\d{5}(?:-\d{4})?'
    for match in re.finditer(address_pattern, text):
        entities.append({
            'Type': 'ADDRESS',
            'originalData': match.group(),
            'BeginOffset': match.start(),
            'EndOffset': match.end(),
            'Score': 0.9
        })
    
    # HIPAA Identifier 8: Medical Record Numbers
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
    
    # HIPAA Identifier 9: Health plan beneficiary numbers
    insurance_patterns = [
        r'Insurance ID:\s*([A-Z0-9]+)',
        r'\b(?:Member ID|Policy Number)[\s:#-]*([A-Z0-9-]+)\b',
        r'\b[A-Z]{1,3}\d{6,12}\b'  # Common insurance ID format
    ]
    for pattern in insurance_patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            # For the first two patterns, use group 1
            if match.lastindex:
                entities.append({
                    'Type': 'INSURANCE_ID',
                    'originalData': match.group(1),
                    'BeginOffset': match.start(1),
                    'EndOffset': match.end(1),
                    'Score': 0.95
                })
            else:
                # Check context for the third pattern
                context = text[max(0, match.start()-20):min(len(text), match.end()+20)].lower()
                if any(word in context for word in ['insurance', 'member', 'policy', 'beneficiary']):
                    entities.append({
                        'Type': 'INSURANCE_ID',
                        'originalData': match.group(),
                        'BeginOffset': match.start(),
                        'EndOffset': match.end(),
                        'Score': 0.85
                    })
    
    # HIPAA Identifier 11: Certificate/License numbers
    license_pattern = r'\b(?:License|Certificate)[\s#:]*([A-Z0-9-]+)\b'
    for match in re.finditer(license_pattern, text, re.IGNORECASE):
        entities.append({
            'Type': 'LICENSE_NUMBER',
            'originalData': match.group(),
            'BeginOffset': match.start(),
            'EndOffset': match.end(),
            'Score': 0.9
        })
    
    # HIPAA Identifier 12: Vehicle identifiers
    vehicle_patterns = [
        r'\b(?:License Plate|Plate)[\s:#]*([A-Z0-9-]+)\b',
        r'\bVIN[\s:#]*([A-Z0-9]{17})\b'
    ]
    for pattern in vehicle_patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            entities.append({
                'Type': 'VEHICLE_ID',
                'originalData': match.group(),
                'BeginOffset': match.start(),
                'EndOffset': match.end(),
                'Score': 0.95
            })
    
    # HIPAA Identifier 13: Device identifiers and serial numbers
    device_patterns = [
        r'\b(?:Serial Number|Serial|SN)[\s:#]*([A-Z0-9-]+)\b',
        r'\b(?:Device ID|Device)[\s:#]*([A-Z0-9-]+)\b',
        r'\b(?:Pacemaker|Pump|Implant)\s+(?:ID|Serial)[\s:#]*([A-Z0-9-]+)\b'
    ]
    for pattern in device_patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            entities.append({
                'Type': 'DEVICE_ID',
                'originalData': match.group(),
                'BeginOffset': match.start(),
                'EndOffset': match.end(),
                'Score': 0.95
            })
    
    # HIPAA Identifier 14: URLs
    url_pattern = r'https?://[^\s]+'
    for match in re.finditer(url_pattern, text):
        entities.append({
            'Type': 'URL',
            'originalData': match.group(),
            'BeginOffset': match.start(),
            'EndOffset': match.end(),
            'Score': 0.99
        })
    
    # HIPAA Identifier 15: IP addresses
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    for match in re.finditer(ip_pattern, text):
        entities.append({
            'Type': 'IP_ADDRESS',
            'originalData': match.group(),
            'BeginOffset': match.start(),
            'EndOffset': match.end(),
            'Score': 0.95
        })
    
    # HIPAA Identifier 16: Biometric identifiers
    biometric_patterns = [
        r'\b(?:Fingerprint|Retinal|Voiceprint|Facial Recognition)[\s:]*(ID)?[\s:#]*([A-Z0-9-]+)\b'
    ]
    for pattern in biometric_patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            entities.append({
                'Type': 'BIOMETRIC_ID',
                'originalData': match.group(),
                'BeginOffset': match.start(),
                'EndOffset': match.end(),
                'Score': 0.95
            })
    
    # HIPAA Identifier 18: Any other unique identifying number
    # This includes clinical trial identifiers
    trial_pattern = r'\bNCT\d{8}\b'
    for match in re.finditer(trial_pattern, text):
        entities.append({
            'Type': 'CLINICAL_TRIAL_ID',
            'originalData': match.group(),
            'BeginOffset': match.start(),
            'EndOffset': match.end(),
            'Score': 0.95
        })
    
    # Employee IDs
    employee_pattern = r'\b(?:Employee ID|EID)[\s:#]*([A-Z0-9-]+)\b'
    for match in re.finditer(employee_pattern, text, re.IGNORECASE):
        entities.append({
            'Type': 'EMPLOYEE_ID',
            'originalData': match.group(),
            'BeginOffset': match.start(),
            'EndOffset': match.end(),
            'Score': 0.9
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
    Only handles HIPAA identifiers, not medical information.
    """
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
    elif entity_type == 'MRN':
        # Generate medical record number
        return 'faker', f"MRN-{fake.random_number(digits=8)}"
    elif entity_type == 'INSURANCE_ID':
        # Generate insurance ID
        prefix = random.choice(['POL', 'MEM', 'GRP'])
        return 'faker', f"{prefix}{fake.random_number(digits=9)}"
    elif entity_type == 'LICENSE_NUMBER':
        return 'faker', fake.license_plate()
    elif entity_type == 'VEHICLE_ID':
        # Generate VIN-like identifier
        return 'faker', ''.join(random.choices(string.ascii_uppercase + string.digits, k=17))
    elif entity_type == 'DEVICE_ID':
        # Generate device serial number
        return 'faker', f"SN-{fake.random_number(digits=10)}"
    elif entity_type == 'BIOMETRIC_ID':
        return 'faker', f"BIO-{fake.random_number(digits=12)}"
    elif entity_type == 'CLINICAL_TRIAL_ID':
        return 'faker', f"NCT{fake.random_number(digits=8)}"
    elif entity_type == 'EMPLOYEE_ID':
        return 'faker', f"EMP{fake.random_number(digits=6)}"
    elif entity_type == 'DOB':
        # Generate a date of birth between 18 and 90 years ago
        days_ago = random.randint(18*365, 90*365)
        dob = datetime.now() - timedelta(days=days_ago)
        return 'faker', dob.strftime('%m/%d/%Y')
    else:
        # Generic fallback for any other unique identifier
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
            
            # Store the fake data with the entity for later use
            entity['fakeData'] = fake_data
            
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
, False),
    ]
    
    # Common medical/non-name terms to exclude
    medical_terms = [
        'Type', 'Diabetes', 'Hypertension', 'Blood', 'Pressure', 'Heart', 'Rate',
        'Glucose', 'Insulin', 'Metformin', 'Lisinopril', 'Daily', 'Twice',
        'Morning', 'Evening', 'January', 'February', 'March', 'April', 'May', 'June',
        'July', 'August', 'September', 'October', 'November', 'December',
        'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday',
        'North', 'South', 'East', 'West', 'Central', 'General', 'Hospital',
        'Clinic', 'Center', 'Medical', 'Health', 'Care', 'Service', 'Department'
    ]
    
    for pattern in name_patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            name_start = match.start(1)
            name_end = match.end(1)
            
            # Check if this name is a healthcare provider
            is_provider = any(name_start >= ps and name_end <= pe for ps, pe in provider_spans)
            
            if not is_provider:
                name = match.group(1)
                entities.append({
                    'Type': 'NAME',
                    'originalData': name,
                    'BeginOffset': name_start,
                    'EndOffset': name_end,
                    'Score': 0.95
                })
    
    # HIPAA Identifier 3: Email addresses
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    for match in re.finditer(email_pattern, text):
        entities.append({
            'Type': 'EMAIL',
            'originalData': match.group(),
            'BeginOffset': match.start(),
            'EndOffset': match.end(),
            'Score': 0.99
        })
    
    # HIPAA Identifier 4: Phone numbers
    phone_patterns = [
        r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
        r'\b\(\d{3}\)\s*\d{3}[-.]?\d{4}\b',
        r'\b\+?1?\s*\(?(\d{3})\)?[-.\s]?(\d{3})[-.\s]?(\d{4})\b'
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
    
    # HIPAA Identifier 5: Fax numbers (same as phone pattern)
    # Already covered by phone patterns above
    
    # HIPAA Identifier 7: Social Security Numbers
    ssn_pattern = r'\b\d{3}-\d{2}-\d{4}\b'
    for match in re.finditer(ssn_pattern, text):
        entities.append({
            'Type': 'SSN',
            'originalData': match.group(),
            'BeginOffset': match.start(),
            'EndOffset': match.end(),
            'Score': 0.98
        })
    
    # HIPAA Identifier 3: Dates (except year)
    date_patterns = [
        r'\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b',
        r'\b\d{2,4}[/-]\d{1,2}[/-]\d{1,2}\b',
        r'\b\d{1,2}\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{2,4}\b',
        r'\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},?\s+\d{2,4}\b'
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
    
    # HIPAA Identifier 10: Account numbers (credit cards)
    cc_pattern = r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'
    for match in re.finditer(cc_pattern, text):
        entities.append({
            'Type': 'CREDIT_DEBIT_NUMBER',
            'originalData': match.group(),
            'BeginOffset': match.start(),
            'EndOffset': match.end(),
            'Score': 0.95
        })
    
    # HIPAA Identifier 2: Geographic subdivisions - ZIP codes
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
    
    # HIPAA Identifier 2: Geographic subdivisions - Addresses
    address_pattern = r'\b\d+\s+[A-Za-z\s]+(?:St|Street|Ave|Avenue|Rd|Road|Dr|Drive|Ln|Lane|Blvd|Boulevard|Way|Court|Ct|Plaza|Place|Pl)\.?\s*,?\s*[A-Za-z\s]+,?\s*[A-Z]{2}\s+\d{5}(?:-\d{4})?'
    for match in re.finditer(address_pattern, text):
        entities.append({
            'Type': 'ADDRESS',
            'originalData': match.group(),
            'BeginOffset': match.start(),
            'EndOffset': match.end(),
            'Score': 0.9
        })
    
    # HIPAA Identifier 8: Medical Record Numbers
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
    
    # HIPAA Identifier 9: Health plan beneficiary numbers
    insurance_patterns = [
        r'Insurance ID:\s*([A-Z0-9]+)',
        r'\b(?:Member ID|Policy Number)[\s:#-]*([A-Z0-9-]+)\b',
        r'\b[A-Z]{1,3}\d{6,12}\b'  # Common insurance ID format
    ]
    for pattern in insurance_patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            # For the first two patterns, use group 1
            if match.lastindex:
                entities.append({
                    'Type': 'INSURANCE_ID',
                    'originalData': match.group(1),
                    'BeginOffset': match.start(1),
                    'EndOffset': match.end(1),
                    'Score': 0.95
                })
            else:
                # Check context for the third pattern
                context = text[max(0, match.start()-20):min(len(text), match.end()+20)].lower()
                if any(word in context for word in ['insurance', 'member', 'policy', 'beneficiary']):
                    entities.append({
                        'Type': 'INSURANCE_ID',
                        'originalData': match.group(),
                        'BeginOffset': match.start(),
                        'EndOffset': match.end(),
                        'Score': 0.85
                    })
    
    # HIPAA Identifier 11: Certificate/License numbers
    license_pattern = r'\b(?:License|Certificate)[\s#:]*([A-Z0-9-]+)\b'
    for match in re.finditer(license_pattern, text, re.IGNORECASE):
        entities.append({
            'Type': 'LICENSE_NUMBER',
            'originalData': match.group(),
            'BeginOffset': match.start(),
            'EndOffset': match.end(),
            'Score': 0.9
        })
    
    # HIPAA Identifier 12: Vehicle identifiers
    vehicle_patterns = [
        r'\b(?:License Plate|Plate)[\s:#]*([A-Z0-9-]+)\b',
        r'\bVIN[\s:#]*([A-Z0-9]{17})\b'
    ]
    for pattern in vehicle_patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            entities.append({
                'Type': 'VEHICLE_ID',
                'originalData': match.group(),
                'BeginOffset': match.start(),
                'EndOffset': match.end(),
                'Score': 0.95
            })
    
    # HIPAA Identifier 13: Device identifiers and serial numbers
    device_patterns = [
        r'\b(?:Serial Number|Serial|SN)[\s:#]*([A-Z0-9-]+)\b',
        r'\b(?:Device ID|Device)[\s:#]*([A-Z0-9-]+)\b',
        r'\b(?:Pacemaker|Pump|Implant)\s+(?:ID|Serial)[\s:#]*([A-Z0-9-]+)\b'
    ]
    for pattern in device_patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            entities.append({
                'Type': 'DEVICE_ID',
                'originalData': match.group(),
                'BeginOffset': match.start(),
                'EndOffset': match.end(),
                'Score': 0.95
            })
    
    # HIPAA Identifier 14: URLs
    url_pattern = r'https?://[^\s]+'
    for match in re.finditer(url_pattern, text):
        entities.append({
            'Type': 'URL',
            'originalData': match.group(),
            'BeginOffset': match.start(),
            'EndOffset': match.end(),
            'Score': 0.99
        })
    
    # HIPAA Identifier 15: IP addresses
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    for match in re.finditer(ip_pattern, text):
        entities.append({
            'Type': 'IP_ADDRESS',
            'originalData': match.group(),
            'BeginOffset': match.start(),
            'EndOffset': match.end(),
            'Score': 0.95
        })
    
    # HIPAA Identifier 16: Biometric identifiers
    biometric_patterns = [
        r'\b(?:Fingerprint|Retinal|Voiceprint|Facial Recognition)[\s:]*(ID)?[\s:#]*([A-Z0-9-]+)\b'
    ]
    for pattern in biometric_patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            entities.append({
                'Type': 'BIOMETRIC_ID',
                'originalData': match.group(),
                'BeginOffset': match.start(),
                'EndOffset': match.end(),
                'Score': 0.95
            })
    
    # HIPAA Identifier 18: Any other unique identifying number
    # This includes clinical trial identifiers
    trial_pattern = r'\bNCT\d{8}\b'
    for match in re.finditer(trial_pattern, text):
        entities.append({
            'Type': 'CLINICAL_TRIAL_ID',
            'originalData': match.group(),
            'BeginOffset': match.start(),
            'EndOffset': match.end(),
            'Score': 0.95
        })
    
    # Employee IDs
    employee_pattern = r'\b(?:Employee ID|EID)[\s:#]*([A-Z0-9-]+)\b'
    for match in re.finditer(employee_pattern, text, re.IGNORECASE):
        entities.append({
            'Type': 'EMPLOYEE_ID',
            'originalData': match.group(),
            'BeginOffset': match.start(),
            'EndOffset': match.end(),
            'Score': 0.9
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
    Only handles HIPAA identifiers, not medical information.
    """
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
    elif entity_type == 'MRN':
        # Generate medical record number
        return 'faker', f"MRN-{fake.random_number(digits=8)}"
    elif entity_type == 'INSURANCE_ID':
        # Generate insurance ID
        prefix = random.choice(['POL', 'MEM', 'GRP'])
        return 'faker', f"{prefix}{fake.random_number(digits=9)}"
    elif entity_type == 'LICENSE_NUMBER':
        return 'faker', fake.license_plate()
    elif entity_type == 'VEHICLE_ID':
        # Generate VIN-like identifier
        return 'faker', ''.join(random.choices(string.ascii_uppercase + string.digits, k=17))
    elif entity_type == 'DEVICE_ID':
        # Generate device serial number
        return 'faker', f"SN-{fake.random_number(digits=10)}"
    elif entity_type == 'BIOMETRIC_ID':
        return 'faker', f"BIO-{fake.random_number(digits=12)}"
    elif entity_type == 'CLINICAL_TRIAL_ID':
        return 'faker', f"NCT{fake.random_number(digits=8)}"
    elif entity_type == 'EMPLOYEE_ID':
        return 'faker', f"EMP{fake.random_number(digits=6)}"
    elif entity_type == 'DOB':
        # Generate a date of birth between 18 and 90 years ago
        days_ago = random.randint(18*365, 90*365)
        dob = datetime.now() - timedelta(days=days_ago)
        return 'faker', dob.strftime('%m/%d/%Y')
    else:
        # Generic fallback for any other unique identifier
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
            
            # Store the fake data with the entity for later use
            entity['fakeData'] = fake_data
            
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
