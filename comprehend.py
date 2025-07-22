import os
import re
from faker import Faker
from faker.generator import random
from typing import List, Dict, Any

# Disable AWS for local testing
comprehend_client = None
comprehend_medical_client = None

comprehend_region_name = os.getenv('AWS_DB_REGION', 'us-east-2')
comprehend_ignore_str = os.getenv('COMPREHEND_IGNORE_PIITYPE', None)
comprehend_ignore_list = []
if comprehend_ignore_str:
    temp_list = comprehend_ignore_str.split(',')
    for i in temp_list:
        comprehend_ignore_list.append(i.strip().upper())

# Medical entity patterns for HIPAA compliance
MEDICAL_PATTERNS = {
    'MRN': [
        r'\b(?:MRN|Medical Record Number|Medical Record|Patient ID)[\s:#]*([A-Z0-9]{3,4}[-]?[A-Z0-9]{2,4}[-]?[A-Z0-9]{4,8})\b',
        r'\b(?:Account|Acct)[\s:#]*([0-9]{6,12})\b',
        r'\b(?:Visit|Encounter)[\s:#]*([A-Z0-9]{8,12})\b'
    ],
    'MEDICATION': [
        r'\b(Metformin\s+[0-9]+(?:\.[0-9]+)?\s*(?:mg|mcg|g|ml|unit[s]?)(?:\s+(?:once|twice|three times|four times)?\s*(?:daily|a day|per day))?)\b',
        r'\b(Metformin|Lisinopril|Atorvastatin|Amlodipine|Metoprolol|Omeprazole|Simvastatin|Losartan|Gabapentin|Hydrochlorothiazide|Levothyroxine|Sertraline|Acetaminophen|Ibuprofen|Aspirin|Warfarin|Furosemide|Prednisone|Insulin|Albuterol)\b',
        r'\b([0-9]+(?:\.[0-9]+)?\s*(?:mg|mcg|g|ml|unit[s]?)(?:\s+(?:once|twice|three times|four times)?\s*(?:daily|a day|per day)))\b',
    ],
    'DIAGNOSIS': [
        r'\b((?:diabetes|hypertension|depression|anxiety|COPD|asthma|pneumonia|UTI|COVID-19|cancer|melanoma|lymphoma|leukemia|diabetes mellitus|coronary artery disease|atrial fibrillation|congestive heart failure|chronic kidney disease|GERD|osteoarthritis|rheumatoid arthritis|bipolar disorder|schizophrenia|PTSD|HIV|hepatitis [ABC])(?:\s+(?:type [12]|stage [IVX]+|grade [0-9]))?)\b',
        r'\b(ICD-?10:?\s*[A-Z][0-9]{2}(?:\.[0-9]{1,2})?)\b'
    ],
    'LAB_VALUE': [
        r'(?:blood sugar|glucose|BS|BG)(?:[^0-9]+)?([0-9]{2,3}(?:\s*-\s*[0-9]{2,3})?)',
        r'(?:A1C|HbA1c|hemoglobin A1c)[\s:]*([0-9]{1,2}(?:\.[0-9]{1,2})?)\s*%?',
        r'(?:blood pressure|BP)[\s:]*([0-9]{2,3}/[0-9]{2,3})\s*(?:mmHg)?',
        r'(?:temperature|temp|T)[\s:]*([0-9]{2,3}(?:\.[0-9]{1,2})?)\s*(?:°?[FC])?',
    ],
    'PROCEDURE': [
        r'\b((?:colonoscopy|endoscopy|bronchoscopy|laparoscopy|arthroscopy|MRI|CT scan|X-ray|ultrasound|echocardiogram|EKG|ECG|mammogram|biopsy|surgery|operation|transplant|dialysis|chemotherapy|radiation therapy|physical therapy|occupational therapy)(?:\s+of\s+(?:the\s+)?(?:brain|chest|abdomen|pelvis|spine|heart|lung|liver|kidney|colon|breast|prostate))?)\b',
        r'\b(CPT:?\s*[0-9]{5})\b'
    ],
    'DEVICE_ID': [
    r'Implanted Devices:\s*([a-zA-Z0-9]+)',                                                           # 1
    r'\b(?:serial number|Serial Number|SN|device ID|implant ID)[\s:#]*([A-Z0-9-]{6,20})\b',         # 2
    r'\b(?:pacemaker|Pacemaker|ICD|insulin pump|prosthetic)\s+(?:Serial Number|serial number|ID|serial)[\s:#]*([A-Z0-9-]{6,20})\b',  # 3
    r'\b([a-zA-Z]{2,}[0-9]{3,})\b'                                                                   # 4
    ],
    'INSURANCE_ID': [
        r'\b(?:Insurance ID|Insurance #|Member ID|Policy #)[\s:#]*([A-Z]{2,4}[0-9]{6,12})\b',
        r'\b(?:Group #|Group Number)[\s:#]*([A-Z0-9]{4,12})\b'
    ],
    'CLINICAL_TRIAL': [
        r'\b(?:study|trial|protocol)[\s:#]*([A-Z0-9-]{5,20})\b',
        r'\b(?:NCT|clinical trial)[\s:#]*([0-9]{8})\b'
    ]
}

# Standard PII patterns for local testing
STANDARD_PII_PATTERNS = {
    'NAME': [
        r'\b(?:Mr\.|Mrs\.|Ms\.|Dr\.|Miss)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\b',
        r'\b(?:Patient|Doctor|Nurse):\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\b'
    ],
    'EMAIL': [
        r'\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b'
    ],
    'PHONE': [
        r'\b(\d{3}[-.]?\d{3}[-.]?\d{4})\b',
        r'\b(\(\d{3}\) ?\d{3}-\d{4})\b'
    ],
    'SSN': [
        r'\b(\d{3}-\d{2}-\d{4})\b'
    ],
    'ADDRESS': [
        r'\b(\d{1,5}\s+[A-Za-z\s]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Circle|Cir|Plaza|Pl)\.?)\b'
    ],
    'ZIP': [
        r'\b(\d{5}(?:-\d{4})?)\b'
    ],
    'TIME': [
        r'\b(\d{1,2}:\d{2}\s*(?:AM|PM|am|pm))\b',
        r'\b(\d{1,2}:\d{2}:\d{2})\b'
    ],
    'DATE': [
        r'\b(\d{1,2}[/-]\d{1,2}[/-]\d{2,4})\b',
        r'\b(\d{4}[/-]\d{1,2}[/-]\d{1,2})\b',
        r'\b((?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2}(?:st|nd|rd|th)?)\b',
        r'\b((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}(?:st|nd|rd|th)?)\b'
    ]
}

# HIPAA Safe Harbor date handling
def mask_dates(text: str) -> str:
    """Remove all date elements except year per HIPAA Safe Harbor"""
    # Full dates
    text = re.sub(r'\b([0-9]{1,2})[/-]([0-9]{1,2})[/-]([0-9]{4})\b', r'XX/XX/\3', text)
    text = re.sub(r'\b([0-9]{4})[/-]([0-9]{1,2})[/-]([0-9]{1,2})\b', r'\1/XX/XX', text)
    # Month names
    months = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December']
    months_short = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
    for month in months + months_short:
        text = re.sub(rf'\b{month}\s+([0-9]{{1,2}}),?\s+([0-9]{{4}})\b', r'XX XX, \2', text, flags=re.IGNORECASE)
    return text

def mask_zip_codes(text: str) -> str:
    """Handle ZIP codes per HIPAA Safe Harbor rules"""
    # List of 3-digit ZIPs that must be changed to 000
    restricted_zips = ['036', '692', '878', '059', '790', '879', '063', '821', '884', '102', '823', '890', '203', '830', '893', '556', '831']
    
    # Match 5 or 9 digit ZIP codes
    def replace_zip(match):
        zip_code = match.group(1)
        first_three = zip_code[:3]
        if first_three in restricted_zips:
            return '00000'
        else:
            return first_three + '**'
    
    text = re.sub(r'\b([0-9]{5})(?:-[0-9]{4})?\b', replace_zip, text)
    return text

def mask_ages_over_89(text: str) -> str:
    """Convert ages over 89 to '90 or older' per HIPAA"""
    def replace_age(match):
        age = int(match.group(1))
        if age > 89:
            return '90 or older'
        return match.group(0)
    
    text = re.sub(r'\b([0-9]{2,3})\s*(?:years old|yo|y/o|years|yrs)\b', replace_age, text, flags=re.IGNORECASE)
    return text


def fake_age():
    return '{} Yrs'.format(random.randint(18, 80))


def fake_unknown():
    return 'XXXXXXXXXX'


def fake_diagnosis():
    """Generate fake diagnosis for medical conditions"""
    conditions = ['Condition A', 'Condition B', 'Medical Issue C', 'Diagnosis D']
    return random.choice(conditions)


def fake_medication():
    """Generate fake medication names"""
    meds = ['Medication A 10mg', 'Drug B 5mg daily', 'Medicine C 100mg', 'Treatment D 50mg']
    return random.choice(meds)


def fake_lab_value():
    """Generate fake lab values"""
    return f"{random.randint(70, 120)} mg/dL"


def fake_mrn():
    """Generate fake medical record number"""
    return f"MRN-{random.randint(100000, 999999)}"


def get_fake_data_generator(piiType):
    fake = Faker()
    
    def fake_date_hipaa():
        """Generate HIPAA-compliant masked date"""
        return 'XX/XX/2025'
    
    def fake_time():
        """Generate fake time"""
        return 'XX:XX PM'
    
    def fake_insurance_id():
        """Generate fake insurance ID"""
        return f'ABC{random.randint(100000000, 999999999)}'
    
    switcher = {
        'NAME': fake.name,
        'ADDRESS': fake.address,
        'EMAIL': fake.email,
        'PHONE': fake.phone_number,
        'SSN': fake.ssn,
        'DATE_TIME': fake.date_time,
        'DATE': fake_date_hipaa,
        'TIME': fake_time,
        'AGE': fake_age,
        'DIAGNOSIS': fake_diagnosis,
        'MEDICATION': fake_medication,
        'LAB_VALUE': fake_lab_value,
        'MRN': fake_mrn,
        'INSURANCE_ID': fake_insurance_id,
        'PROCEDURE': lambda: 'Medical Procedure',
        'DEVICE_ID': lambda: f'DEVICE-{random.randint(100000, 999999)}',
        'CLINICAL_TRIAL': lambda: f'TRIAL-{random.randint(10000, 99999)}'
    }
    return switcher.get(piiType, fake_unknown)


def generate_fake_data(piiType):
    fake_data_generator = get_fake_data_generator(piiType)
    return fake_data_generator.__name__, fake_data_generator()


def detect_medical_entities(text: str) -> List[Dict[str, Any]]:
    """Detect medical entities using regex patterns"""
    entities = []
    
    # Debug: Show DEVICE_ID patterns
    if "implanted" in text.lower():
        print(f"DEBUG: DEVICE_ID has {len(MEDICAL_PATTERNS.get('DEVICE_ID', []))} patterns")
        for i, p in enumerate(MEDICAL_PATTERNS.get('DEVICE_ID', [])):
            print(f"DEBUG: DEVICE_ID pattern {i}: {p}")
    
    for entity_type, patterns in MEDICAL_PATTERNS.items():
        for pattern in patterns:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                # Use captured group if available, otherwise full match
                if match.groups():
                    original_data = match.group(1)
                else:
                    original_data = match.group(0)
                
                print(f"DEBUG: Pattern '{pattern}' matched '{original_data}' as {entity_type}")
                    
                entity = {
                    'Type': entity_type,
                    'BeginOffset': match.start(1) if match.groups() else match.start(),
                    'EndOffset': match.end(1) if match.groups() else match.end(),
                    'originalData': original_data,
                    'Score': 0.95
                }
                entities.append(entity)
    
    return entities, None


def detect_standard_pii(text: str) -> List[Dict[str, Any]]:
    """Detect standard PII using regex patterns for local testing"""
    entities = []
    
    for entity_type, patterns in STANDARD_PII_PATTERNS.items():
        if entity_type in comprehend_ignore_list:
            continue
            
        for pattern in patterns:
            # Use IGNORECASE flag for name patterns
            flags = re.IGNORECASE if entity_type == 'NAME' else 0
            for match in re.finditer(pattern, text, flags):
                entity = {
                    'Type': entity_type,
                    'BeginOffset': match.start(1) if match.groups() else match.start(),
                    'EndOffset': match.end(1) if match.groups() else match.end(),
                    'originalData': match.group(1) if match.groups() else match.group(0),
                    'Score': 0.85
                }
                entities.append(entity)
    
    return entities


def detect_pii_data(text_blob):
    """Enhanced PII detection for local testing without AWS"""
    print(f"\nDEBUG: Detecting PII in text: {text_blob[:100]}...")
    entities = []
    
    # First, detect medical entities and apply HIPAA transformations
    medical_entities, processed_text = detect_medical_entities(text_blob)
    print(f"DEBUG: Found {len(medical_entities)} medical entities")
    entities.extend(medical_entities)
    
    # If text was modified by HIPAA rules, use the processed version
    if processed_text:
        text_blob = processed_text
    
    # Detect standard PII using regex patterns
    standard_entities = detect_standard_pii(text_blob)
    print(f"DEBUG: Found {len(standard_entities)} standard entities")
    entities.extend(standard_entities)
    
    # Sort by start offset and remove overlapping entities
    entities.sort(key=lambda x: (x['BeginOffset'], -x['EndOffset']))
    
    # Remove overlapping entities, keeping the first/longest match
    unique_entities = []
    last_end = -1
    
    for entity in entities:
        if entity['BeginOffset'] >= last_end:
            unique_entities.append(entity)
            print(f"DEBUG: Keeping entity: {entity['Type']} = '{entity['originalData']}'")
            last_end = entity['EndOffset']
    
    return unique_entities


def generate_fake_entities(masterid, entities, rows):
    records = []
    for entity in entities:
        fake_data = None
        for row in rows:
            if row['originalData'].upper() == entity['originalData'].upper():
                fake_data = row['fakeData']
                break

        if fake_data is None:
            for record in records:
                if record['originalData'].upper() == entity['originalData'].upper():
                    fake_data = record['fakeData']
                    break

            if fake_data is None:
                # Generate appropriate fake data based on content
                if entity['Type'] == 'LAB_VALUE':
                    original = entity['originalData'].lower()
                    if 'blood pressure' in original or 'bp' in original or '/' in original:
                        fake_data = '120/80 mmHg'
                    elif 'temperature' in original or 'temp' in original:
                        fake_data = '98.6°F'
                    elif 'blood sugar' in original or 'glucose' in original:
                        fake_data = '110 mg/dL'
                    elif 'a1c' in original:
                        fake_data = '6.5%'
                    else:
                        fake_data = '95 mg/dL'
                    fake_data_generator_name = 'fake_lab_value'
                else:
                    fake_data_generator = get_fake_data_generator(entity['Type'])
                    fake_data = fake_data_generator()
                    fake_data_generator_name = fake_data_generator.__name__

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

        entity['fakeData'] = fake_data

    return records


def anonymize(text_blob, entities):
    anonymized_text = ''
    offset = 0
    for entity in entities:
        anonymized_text = anonymized_text + text_blob[offset:entity['BeginOffset']] + str(entity['fakeData'])
        offset = entity['EndOffset']
    anonymized_text = anonymized_text + text_blob[offset:]
    return anonymized_text


def de_anonymize(anonymized_text_blob, rows):
    for row in rows:
        anonymized_text_blob = anonymized_text_blob.replace(row['fakeData'], row['originalData'])
    return anonymized_text_blob
