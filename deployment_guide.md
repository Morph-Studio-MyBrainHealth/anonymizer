# HIPAA-Compliant Medical Data Anonymizer - Deployment Guide

## Overview

This guide covers deployment and usage of the HIPAA-compliant anonymization system for healthcare chatbots. The system anonymizes only the 18 HIPAA Safe Harbor identifiers while preserving all medical information needed for accurate healthcare responses.

## Key Features

- ✅ **HIPAA Safe Harbor Compliant**: Removes all 18 PHI identifiers
- ✅ **Medical Information Preserved**: Keeps diagnoses, medications, lab values, clinical notes
- ✅ **Provider Name Preservation**: Healthcare provider names are NOT anonymized
- ✅ **Reversible Anonymization**: Can restore original data when authorized
- ✅ **Audit Trail**: Complete logging for HIPAA compliance
- ✅ **JSON Support**: Handles structured medical data

## Quick Start

### 1. Installation

```bash
# Clone the repository
git clone <your-repo-url>
cd medical-anonymizer

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Run Tests

```bash
# Run HIPAA compliance tests
python test_hipaa_compliance.py

# Expected output:
# ✓ All tests passed! The anonymizer is HIPAA compliant.
```

### 3. Start Test Interface

```bash
python chat_app.py
# Access at http://localhost:5000
```

## Usage Examples

### Python API - Text Anonymization

```python
from anonymizer import anonymizer, de_anonymizer

# Original text with PHI and medical information
text = """
Patient: John Smith, DOB: 03/15/1975, MRN: ABC-123456
Diagnosis: Type 2 Diabetes (E11.9)
Medications: Metformin 1000mg BID
Provider: Dr. Sarah Johnson
"""

# Anonymize (only PHI is changed, medical info preserved)
result = anonymizer("user123", "USER_ID", text)
anonymized = json.loads(result['body'])['result']

print(anonymized)
# Output:
# Patient: Michael Davis, DOB: XX/XX/1975, MRN: MRN-78901234
# Diagnosis: Type 2 Diabetes (E11.9)    <- Preserved!
# Medications: Metformin 1000mg BID      <- Preserved!
# Provider: Dr. Sarah Johnson            <- Preserved!

# De-anonymize when authorized
result = de_anonymizer("user123", "USER_ID", anonymized)
original = json.loads(result['body'])['result']
```

### Python API - JSON Anonymization

```python
from anonymizer import anonymize_json, de_anonymize_json

# Medical record with PHI and clinical data
patient_data = {
    "patient": {
        "name": "Jane Doe",
        "mrn": "MRN-123456"
    },
    "clinical": {
        "diagnosis": "Hypertension (I10)",
        "medications": ["Lisinopril 20mg daily"],
        "lab_results": {
            "bp": "140/90",
            "glucose": 126
        }
    }
}

# Anonymize - only patient identifiers change
result = anonymize_json("user123", "USER_ID", patient_data)
anonymized = json.loads(result['body'])['result']

# Medical information is fully preserved!
assert anonymized['clinical'] == patient_data['clinical']
```

### REST API Usage

```bash
# Start the Flask server
python chat_app.py

# Anonymize text
curl -X POST http://localhost:5000/anonymize \
  -H "Content-Type: application/json" \
  -d '{"text": "Patient John Smith has diabetes"}'

# Anonymize JSON
curl -X POST http://localhost:5000/anonymize_json \
  -H "Content-Type: application/json" \
  -d '{"json_data": {"patient_name": "John Smith", "diagnosis": "diabetes"}}'
```

## What Gets Anonymized vs Preserved

### ❌ Anonymized (HIPAA Identifiers)

| Category | Examples | Anonymization Method |
|----------|----------|---------------------|
| Names | John Smith, Mary Jones | Random names |
| Addresses | 123 Main St, Boston, MA | Random addresses |
| Dates | 03/15/2025, April 20th | XX/XX/YYYY (keep year) |
| Phone | 555-123-4567 | Random phone |
| Email | john@email.com | Random email |
| SSN | 123-45-6789 | Random SSN |
| MRN | ABC-123456 | Random MRN |
| Insurance ID | BCB987654321 | Random ID |

### ✅ Preserved (Medical Information)

| Category | Examples |
|----------|----------|
| Diagnoses | Type 2 Diabetes, Hypertension, Depression |
| ICD Codes | E11.9, I10, F32.9 |
| Medications | Metformin 1000mg BID, Lisinopril 20mg |
| Lab Values | Glucose: 156 mg/dL, HbA1c: 8.2% |
| Vital Signs | BP: 140/90, HR: 78, Temp: 98.6°F |
| Clinical Notes | "Alert and oriented", "No acute distress" |
| Assessment Scores | MMSE: 24/30, PHQ-9: 15 |
| Provider Names | Dr. Sarah Johnson, Patricia Brown, RN |

## Production Deployment

### 1. Environment Setup

```bash
# Production environment variables
export DB_HOST=your-rds-endpoint
export DB_USER=your-db-user
export DB_PASSWORD=your-db-password
export DB_NAME=hipaa_anonymizer
export AWS_REGION=us-east-1
```

### 2. Database Setup

```sql
-- Run table creation scripts
mysql -h $DB_HOST -u $DB_USER -p < create_tables.sql
```

### 3. AWS Lambda Deployment

```python
# serverless.yml
service: hipaa-anonymizer

provider:
  name: aws
  runtime: python3.9
  region: us-east-1
  environment:
    DB_HOST: ${env:DB_HOST}
    DB_USER: ${env:DB_USER}
    DB_PASSWORD: ${env:DB_PASSWORD}

functions:
  anonymize:
    handler: anonymizer.lambda_handler
    events:
      - http:
          path: /anonymize
          method: post
```

### 4. Security Configuration

```python
# Enable encryption at rest
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY')

# Configure audit logging
AUDIT_CONFIG = {
    'enabled': True,
    'retention_days': 2555,  # 7 years for HIPAA
    'log_access': True,
    'log_modifications': True
}
```

## Compliance Checklist

- [ ] **HIPAA Safe Harbor**: Only the 18 identifiers are anonymized
- [ ] **Medical Preservation**: All clinical data remains unchanged
- [ ] **Audit Trail**: All PHI access is logged
- [ ] **Encryption**: Data encrypted in transit and at rest
- [ ] **Access Control**: Role-based access to de-anonymization
- [ ] **BAA**: Business Associate Agreement with cloud providers
- [ ] **Retention**: 7-year audit log retention
- [ ] **Testing**: Regular compliance validation

## Integration with Healthcare Chatbot

```python
# Example integration
class HealthcareChatbot:
    def __init__(self):
        self.anonymizer_user = "chatbot_system"
        
    def process_user_message(self, user_id, message):
        # Anonymize incoming message
        anon_result = anonymizer(user_id, "USER_ID", message)
        anon_message = json.loads(anon_result['body'])['result']
        
        # Send anonymized message to LLM
        llm_response = self.llm.generate(anon_message)
        
        # Response contains no PHI, safe to return
        return llm_response
        
    def get_patient_history(self, user_id, anonymized_history):
        # De-anonymize when displaying to authorized users
        result = de_anonymizer(user_id, "USER_ID", anonymized_history)
        return json.loads(result['body'])['result']
```

## Monitoring and Alerts

```python
# Set up CloudWatch alarms
ALARMS = {
    'failed_anonymization': {
        'metric': 'AnonymizationErrors',
        'threshold': 5,
        'period': 300
    },
    'unauthorized_access': {
        'metric': 'UnauthorizedDeAnonymization',
        'threshold': 1,
        'period': 60
    }
}
```

## Troubleshooting

### Common Issues

1. **Medical terms being anonymized**
   - Check: Ensure using updated `comprehend.py` that excludes medical entities
   - Fix: Medical terms should NOT be in the entity detection patterns

2. **Provider names being anonymized**
   - Check: Look for provider titles (Dr., MD, RN) in the text
   - Fix: Provider detection regex should exclude these patterns

3. **Incomplete de-anonymization**
   - Check: Ensure same identity/identityType used for both operations
   - Fix: Verify PII mappings exist in database

### Debug Mode

```python
# Enable debug logging
DEBUG_MODE = True  # In anonymizer.py

# Check entity detection
from comprehend import detect_pii_data
entities = detect_pii_data("Dr. Smith treated John Doe's diabetes")
print(f"Detected entities: {entities}")
# Should only detect "John Doe", not "Dr. Smith" or "diabetes"
```

## Support

- Documentation: See README.md
- Issues: GitHub Issues
- Security: security@yourcompany.com
- Compliance: compliance@yourcompany.com

## Next Steps

1. Run compliance tests: `python test_hipaa_compliance.py`
2. Test with your medical data using `chat_app.py`
3. Deploy to your environment
4. Configure audit logging and monitoring
5. Schedule regular compliance audits

Remember: This system is designed to preserve medical information while protecting patient privacy. Always verify that clinical data passes through unchanged!
