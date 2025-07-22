# Medical PHI Pattern Implementation Examples
# Shows how to use the updated anonymizer for healthcare data

import json
from comprehend import detect_pii_data, anonymize, generate_fake_entities
from db_methods import get_piimaster_uuid, get_piientity_data

# Example 1: Clinical conversation with multiple PHI types
def example_clinical_conversation():
    clinical_conversation = """
Patient: John Smith, MRN: ABC-123-456789
DOB: 03/15/1975, Phone: 555-123-4567
Chief Complaint: Patient presents with uncontrolled diabetes.
Current Medications: Metformin 1000mg twice daily, Lisinopril 10mg daily
Latest Labs: Glucose 245 mg/dL, A1C 9.2%, Blood pressure 150/95
Diagnosis: Type 2 Diabetes Mellitus (ICD-10: E11.9), Hypertension
Scheduled for colonoscopy on 04/15/2025 at 2:30 PM
"""
    
    # Detect all PHI/PII
    entities = detect_pii_data(clinical_conversation)
    
    print("Detected Entities:")
    for entity in entities:
        print(f"- Type: {entity['Type']}, Data: {entity['originalData']}")
    
    # Generate fake data
    masterid = get_piimaster_uuid("patient123", "PATIENT_ID")
    rows = get_piientity_data(masterid)
    pii_records = generate_fake_entities(masterid, entities, rows)
    
    # Anonymize
    anonymized = anonymize(clinical_conversation, entities)
    print("\nAnonymized text:")
    print(anonymized)
    
    return entities, anonymized


# Example 2: Complex medication regimen
def example_medication_patterns():
    medication_text = """
Current Medications:
1. Metformin 1000mg PO BID with meals
2. Insulin Glargine 24 units subcutaneous at bedtime
3. Lisinopril 10mg daily for hypertension
4. Atorvastatin 40mg at bedtime
5. Aspirin 81mg daily
6. Gabapentin 300mg TID for neuropathy
PRN: Albuterol inhaler 2 puffs every 4 hours as needed for wheezing
"""
    
    entities = detect_pii_data(medication_text)
    
    print("Detected Medications:")
    for entity in entities:
        if entity['Type'] == 'MEDICATION':
            print(f"- {entity['originalData']}")
    
    return entities


# Example 3: Lab results with critical values
def example_lab_values():
    lab_report = """
Lab Results from 03/20/2025:
- Glucose: 320 mg/dL (HIGH - Critical)
- A1C: 11.2% (Goal <7%)
- Creatinine: 2.1 mg/dL (elevated)
- eGFR: 38 mL/min (Stage 3b CKD)
- Hemoglobin: 9.2 g/dL (LOW)
- WBC: 15.3 K/uL (elevated)
- Blood pressure: 165/102 mmHg
- Temperature: 101.5°F
- Heart rate: 108 bpm
"""
    
    entities = detect_pii_data(lab_report)
    
    print("Detected Lab Values:")
    for entity in entities:
        if entity['Type'] == 'LAB_VALUE':
            print(f"- {entity['originalData']}")
    
    # The dates are automatically masked per HIPAA
    masterid = "test123"
    fake_entities = generate_fake_entities(masterid, entities, [])
    anonymized = anonymize(lab_report, entities)
    
    print("\nAnonymized lab report:")
    print(anonymized)
    
    return entities


# Example 4: Device and trial identifiers
def example_device_trial_ids():
    device_text = """
Patient has the following implanted devices:
- Pacemaker: Serial Number PM-789456123
- Insulin pump: Device ID INS-456789ABC
- Continuous Glucose Monitor: SN CGM-123456

Enrolled in clinical trial: NCT12345678
Study protocol: DIAB-2025-001
"""
    
    entities = detect_pii_data(device_text)
    
    print("Detected Device/Trial IDs:")
    for entity in entities:
        if entity['Type'] in ['DEVICE_ID', 'CLINICAL_TRIAL']:
            print(f"- Type: {entity['Type']}, ID: {entity['originalData']}")
    
    return entities


# Example 5: Real-world clinical note
def example_clinical_note():
    clinical_note = """
Patient: Jane Doe (MRN: 123-45-67890)
Visit Date: 03/25/2025
Provider: Dr. Smith, NPI: 1234567890

CHIEF COMPLAINT: Follow-up for diabetes and hypertension

HPI: 68-year-old female with Type 2 DM and HTN returns for routine follow-up. 
Reports glucose readings 180-250 mg/dL. Taking Metformin 1000mg BID but admits 
poor compliance. BP at home averaging 145/90.

CURRENT MEDICATIONS:
- Metformin 1000mg PO BID
- Lisinopril 20mg daily
- Amlodipine 5mg daily
- Atorvastatin 40mg QHS

VITALS:
BP: 152/94, HR: 82, Temp: 98.6°F, Weight: 185 lbs

LABS (03/20/2025):
- A1C: 9.8% (was 8.2% three months ago)
- Glucose: 245 mg/dL
- Creatinine: 1.4 mg/dL
- eGFR: 52 mL/min

ASSESSMENT/PLAN:
1. Uncontrolled T2DM - Increase Metformin to 1000mg TID, add Jardiance 10mg daily
2. Hypertension - Increase Lisinopril to 30mg daily
3. Follow up in 3 months with repeat A1C

Next appointment: 06/25/2025 at 10:30 AM
"""
    
    # Process with full context
    context = {
        'purpose': 'healthcare_provision',
        'user_id': 'provider123',
        'access_reason': 'patient_care'
    }
    
    # Import the anonymizer function
    from anonymizer import anonymizer
    
    result = anonymizer("jane.doe@email.com", "EMAIL", clinical_note, context)
    
    print("Anonymization Result:")
    result_body = json.loads(result['body'])
    print(f"Status: {result['statusCode']}")
    print(f"Entities detected: {result_body['entities_detected']}")
    print(f"Compliance status: {result_body['compliance']}")
    print("\nAnonymized note:")
    print(result_body['result'][:500] + "...")
    
    return result


# Example 6: Pattern testing for edge cases
def test_edge_cases():
    edge_cases = [
        # MRN variations
        "MRN:123456789",
        "Medical Record Number: ABC-123-4567",
        "Patient ID: 987654321",
        "Account #: 123456789012",
        
        # Medication with complex instructions
        "Insulin sliding scale: BS <150 no insulin, 151-200 2 units, 201-250 4 units",
        "Warfarin 5mg Mon/Wed/Fri, 2.5mg other days",
        "Prednisone taper: 40mg x 3 days, 30mg x 3 days, then decrease by 10mg q3days",
        
        # Lab values with ranges
        "Glucose 95 mg/dL (normal 70-100)",
        "TSH 12.5 mIU/L (normal 0.4-4.0)",
        "INR 3.2 (therapeutic range 2-3)",
        
        # Ages requiring special handling
        "92 year old patient",  # Should become "90 or older"
        "Age: 95 years",  # Should become "90 or older"
        "85 yo male",  # Should remain as-is
        
        # ZIP codes requiring masking
        "Address: 123 Main St, Boston, MA 02101",  # Should become 021**
        "ZIP: 03601",  # Restricted ZIP, should become 00000
        
        # Complex dates
        "Surgery scheduled for April 15th, 2025",
        "Last visit: 01/15/2025",
        "Follow-up in 3 months"
    ]
    
    print("Edge Case Testing:")
    for test_case in edge_cases:
        entities = detect_pii_data(test_case)
        if entities:
            # Generate fake data for testing
            masterid = "test_edge"
            fake_entities = generate_fake_entities(masterid, entities, [])
            anonymized = anonymize(test_case, entities)
            print(f"\nOriginal: {test_case}")
            print(f"Anonymized: {anonymized}")
            print(f"Entities: {[f'{e['Type']}: {e['originalData']}' for e in entities]}")


# Example 7: Batch processing for multiple records
def example_batch_processing():
    patient_records = [
        {
            "id": "patient1",
            "text": "John Smith, DOB: 01/15/1980, diagnosed with diabetes, A1C 8.5%"
        },
        {
            "id": "patient2", 
            "text": "Jane Doe, MRN: 456789, taking Metformin 500mg BID, BP 130/85"
        },
        {
            "id": "patient3",
            "text": "Bob Johnson, age 92, scheduled for MRI on 04/20/2025"
        }
    ]
    
    from anonymizer import anonymizer
    
    results = []
    for record in patient_records:
        result = anonymizer(
            record["id"], 
            "PATIENT_ID", 
            record["text"],
            {"purpose": "quality_improvement"}
        )
        results.append({
            "id": record["id"],
            "status": result["statusCode"],
            "anonymized": json.loads(result["body"])["result"]
        })
    
    print("Batch Processing Results:")
    for result in results:
        print(f"\nPatient {result['id']}:")
        print(f"Status: {result['status']}")
        print(f"Anonymized: {result['anonymized']}")
    
    return results


# Run examples
if __name__ == "__main__":
    print("=== Example 1: Clinical Conversation ===")
    example_clinical_conversation()
    
    print("\n=== Example 2: Medication Patterns ===")
    example_medication_patterns()
    
    print("\n=== Example 3: Lab Values ===")
    example_lab_values()
    
    print("\n=== Example 4: Device and Trial IDs ===")
    example_device_trial_ids()
    
    print("\n=== Example 5: Clinical Note ===")
    example_clinical_note()
    
    print("\n=== Example 6: Edge Cases ===")
    test_edge_cases()
    
    print("\n=== Example 7: Batch Processing ===")
    example_batch_processing()