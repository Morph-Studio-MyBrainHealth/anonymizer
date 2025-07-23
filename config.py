"""
HIPAA-Compliant Anonymizer Configuration
Defines what should and should not be anonymized
"""

# HIPAA Safe Harbor Identifiers (18 types that MUST be anonymized)
HIPAA_IDENTIFIERS = {
    # 1. Names
    'NAME': {
        'description': 'Names of individuals, relatives, employers, household members',
        'examples': ['John Smith', 'Mary Johnson', 'ABC Company'],
        'exceptions': ['Healthcare provider names', 'Doctor names', 'Nurse names']
    },
    
    # 2. Geographic subdivisions
    'ADDRESS': {
        'description': 'All geographic subdivisions smaller than state',
        'examples': ['123 Main St', 'Chicago', 'Cook County'],
        'exceptions': ['State names']
    },
    'ZIP': {
        'description': 'ZIP codes',
        'special_handling': 'First 3 digits allowed if area > 20,000 people',
        'restricted_prefixes': ['036', '692', '878', '059', '790', '879', '063', 
                               '821', '884', '102', '823', '890', '203', '830', 
                               '893', '556', '831']
    },
    
    # 3. Dates
    'DATE': {
        'description': 'All dates except year',
        'examples': ['01/15/2023', 'March 15', 'admission date'],
        'special_handling': 'Keep only year; aggregate ages 90+ to "90 or above"'
    },
    
    # 4-5. Contact information
    'PHONE_NUMBER': {
        'description': 'Telephone and fax numbers',
        'examples': ['555-123-4567', '(555) 123-4567']
    },
    'EMAIL': {
        'description': 'Email addresses',
        'examples': ['john@example.com']
    },
    
    # 7-11. Identification numbers
    'SSN': {
        'description': 'Social Security Numbers',
        'examples': ['123-45-6789']
    },
    'MRN': {
        'description': 'Medical Record Numbers',
        'examples': ['MRN-123456', 'ABC-789012']
    },
    'INSURANCE_ID': {
        'description': 'Health plan beneficiary numbers',
        'examples': ['BCB123456789', 'Policy# 12345']
    },
    'LICENSE_NUMBER': {
        'description': 'Certificate or license numbers',
        'examples': ['DL-123456', 'License# ABC123']
    },
    
    # 12-13. Vehicle identifiers
    'VEHICLE_ID': {
        'description': 'Vehicle identifiers and license plates',
        'examples': ['ABC-123', 'VIN: 1HGCM82633A123456']
    },
    
    # 14-16. Web and biometric identifiers
    'URL': {
        'description': 'Web URLs',
        'examples': ['https://patient-portal.com/john123']
    },
    'IP_ADDRESS': {
        'description': 'IP addresses',
        'examples': ['192.168.1.1']
    },
    'BIOMETRIC_ID': {
        'description': 'Biometric identifiers',
        'examples': ['Fingerprint ID: 12345', 'Retinal scan: ABC']
    },
    
    # 13. Device identifiers
    'DEVICE_ID': {
        'description': 'Device identifiers and serial numbers',
        'examples': ['Pacemaker SN: 12345', 'Pump ID: ABC-789']
    },
    
    # 17. Photos
    'PHOTO': {
        'description': 'Full face photos and comparable images',
        'note': 'Not handled by text anonymizer'
    },
    
    # 18. Other unique identifiers
    'CLINICAL_TRIAL_ID': {
        'description': 'Clinical trial numbers',
        'examples': ['NCT12345678']
    },
    'EMPLOYEE_ID': {
        'description': 'Employee IDs',
        'examples': ['EMP123456', 'Staff ID: 789']
    },
    'OTHER': {
        'description': 'Any other unique identifying number or code'
    }
}

# Medical information that MUST BE PRESERVED (not anonymized)
PRESERVED_MEDICAL_INFO = {
    'DIAGNOSES': {
        'description': 'Medical diagnoses and conditions',
        'examples': [
            'Type 2 Diabetes Mellitus',
            'Hypertension',
            'Major Depressive Disorder',
            'Alzheimer\'s Disease',
            'COVID-19'
        ]
    },
    'ICD_CODES': {
        'description': 'ICD diagnostic codes',
        'examples': ['E11.9', 'I10', 'F32.9', 'G30.9', 'U07.1']
    },
    'MEDICATIONS': {
        'description': 'Medication names, dosages, and frequencies',
        'examples': [
            'Metformin 1000mg BID',
            'Lisinopril 20mg daily',
            'Sertraline 50mg QD',
            'Insulin Glargine 24 units'
        ]
    },
    'LAB_VALUES': {
        'description': 'Laboratory test results and values',
        'examples': [
            'Glucose: 156 mg/dL',
            'HbA1c: 8.2%',
            'Creatinine: 1.2 mg/dL',
            'TSH: 3.5 mIU/L'
        ]
    },
    'VITAL_SIGNS': {
        'description': 'Vital signs and measurements',
        'examples': [
            'Blood Pressure: 140/90',
            'Heart Rate: 78 bpm',
            'Temperature: 98.6°F',
            'O2 Sat: 96%'
        ]
    },
    'PROCEDURES': {
        'description': 'Medical procedures and tests',
        'examples': [
            'Colonoscopy',
            'MRI brain',
            'Lumbar puncture',
            'Cardiac catheterization'
        ]
    },
    'CLINICAL_OBSERVATIONS': {
        'description': 'Clinical findings and observations',
        'examples': [
            'No acute distress',
            'Alert and oriented x3',
            'Lungs clear to auscultation',
            'No focal neurological deficits'
        ]
    },
    'ASSESSMENT_SCORES': {
        'description': 'Clinical assessment scores',
        'examples': [
            'MMSE: 24/30',
            'PHQ-9: 15',
            'GAD-7: 12',
            'MoCA: 22/30'
        ]
    },
    'PROVIDER_NAMES': {
        'description': 'Healthcare provider names',
        'examples': [
            'Dr. John Smith',
            'Susan Johnson, RN',
            'Dr. Michael Chen, MD',
            'Patricia Brown, NP'
        ]
    }
}

# Keywords that indicate medical content (should not trigger anonymization)
MEDICAL_KEYWORDS = [
    # Conditions
    'diabetes', 'hypertension', 'depression', 'anxiety', 'dementia', 
    'alzheimer', 'cancer', 'copd', 'asthma', 'arthritis',
    
    # Medications (generic names)
    'metformin', 'lisinopril', 'atorvastatin', 'levothyroxine', 
    'amlodipine', 'metoprolol', 'omeprazole', 'simvastatin',
    'losartan', 'gabapentin', 'sertraline', 'insulin',
    
    # Lab tests
    'glucose', 'hba1c', 'creatinine', 'cholesterol', 'triglycerides',
    'hemoglobin', 'platelet', 'sodium', 'potassium', 'tsh',
    
    # Procedures
    'mri', 'ct scan', 'x-ray', 'ultrasound', 'biopsy', 
    'colonoscopy', 'endoscopy', 'catheterization',
    
    # Clinical terms
    'diagnosis', 'prognosis', 'symptom', 'syndrome', 'disorder',
    'chronic', 'acute', 'bilateral', 'unilateral', 'stable',
    
    # Dosage terms
    'mg', 'ml', 'mcg', 'units', 'daily', 'bid', 'tid', 'qid',
    'prn', 'po', 'iv', 'im', 'subcutaneous'
]

# Provider title keywords (names with these titles should NOT be anonymized)
PROVIDER_TITLES = [
    'Dr.', 'Doctor', 'MD', 'DO', 'PhD', 'RN', 'NP', 'PA',
    'Nurse', 'Physician', 'Therapist', 'Psychiatrist', 
    'Psychologist', 'Counselor', 'Pharmacist', 'PharmD',
    'DDS', 'DMD', 'OD', 'DPM', 'DC', 'PT', 'OT', 'SLP'
]

# Configuration flags
CONFIG = {
    'STRICT_HIPAA_MODE': True,  # Only anonymize HIPAA identifiers
    'PRESERVE_PROVIDER_NAMES': True,  # Don't anonymize healthcare providers
    'PRESERVE_MEDICAL_INFO': True,  # Keep all medical information
    'ZIP_CODE_HANDLING': 'HIPAA',  # 'HIPAA' or 'FULL'
    'DATE_HANDLING': 'YEAR_ONLY',  # 'YEAR_ONLY' or 'FULL'
    'AGE_THRESHOLD': 90,  # Aggregate ages above this to "90 or above"
    'AUDIT_LOGGING': True,  # Enable HIPAA audit trail
    'REVERSIBLE': True,  # Allow de-anonymization
}

# Validation rules
VALIDATION_RULES = {
    'MIN_NAME_LENGTH': 3,  # Minimum length to consider as name
    'MIN_MRN_LENGTH': 4,   # Minimum length for MRN
    'REQUIRE_CONSENT': False,  # Require explicit consent for anonymization
    'LOG_ACCESS': True,    # Log all PHI access
}

def is_medical_term(text):
    """Check if text contains medical terminology"""
    text_lower = text.lower()
    return any(keyword in text_lower for keyword in MEDICAL_KEYWORDS)

def is_provider_name(text):
    """Check if text is a healthcare provider name"""
    return any(title in text for title in PROVIDER_TITLES)

def should_preserve(text, context=None):
    """Determine if text should be preserved (not anonymized)"""
    if CONFIG['PRESERVE_MEDICAL_INFO'] and is_medical_term(text):
        return True
    if CONFIG['PRESERVE_PROVIDER_NAMES'] and is_provider_name(text):
        return True
    return False

def get_hipaa_identifier_type(text):
    """Determine which HIPAA identifier type applies to text"""
    # This would be implemented with actual detection logic
    # For now, it's a placeholder
    pass
