#!/usr/bin/env python3
"""
HIPAA Compliance Test Script for Medical Data Anonymizer
Tests that only HIPAA identifiers are anonymized while medical information is preserved
"""

import json
import sys
from collections import OrderedDict
from anonymizer import anonymizer, de_anonymizer, anonymize_json, de_anonymize_json
from comprehend import detect_pii_data

# ANSI color codes for output
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
BOLD = '\033[1m'
RESET = '\033[0m'

def print_test_header(test_name):
    """Print a formatted test header"""
    print(f"\n{BOLD}{BLUE}{'='*60}{RESET}")
    print(f"{BOLD}{BLUE}TEST: {test_name}{RESET}")
    print(f"{BOLD}{BLUE}{'='*60}{RESET}\n")

def print_result(label, value, highlight=False):
    """Print a formatted result"""
    if highlight:
        print(f"{BOLD}{label}:{RESET} {YELLOW}{value}{RESET}")
    else:
        print(f"{BOLD}{label}:{RESET} {value}")

def check_preserved(original, anonymized, field_name):
    """Check if a field was preserved (not anonymized)"""
    if original == anonymized:
        print(f"{GREEN}✓ {field_name} preserved: {original}{RESET}")
        return True
    else:
        print(f"{RED}✗ {field_name} was anonymized: {original} → {anonymized}{RESET}")
        return False

def check_anonymized(original, anonymized, field_name):
    """Check if a field was properly anonymized"""
    if original != anonymized and anonymized and not original in anonymized:
        print(f"{GREEN}✓ {field_name} anonymized: {original} → {anonymized}{RESET}")
        return True
    else:
        print(f"{RED}✗ {field_name} not properly anonymized: {original} → {anonymized}{RESET}")
        return False

def test_text_anonymization():
    """Test basic text anonymization"""
    print_test_header("Text Anonymization - Clinical Note")
    
    test_text = """
Patient: John Smith, DOB: 03/15/1975, MRN: ABC-123456
Phone: 555-123-4567, Email: jsmith@email.com
SSN: 123-45-6789, Insurance ID: BCB987654321

Chief Complaint: Uncontrolled Type 2 Diabetes
Diagnosis: Type 2 Diabetes Mellitus (E11.9), Hypertension (I10)
Medications: 
- Metformin 1000mg BID
- Lisinopril 20mg daily
- Insulin Glargine 24 units at bedtime

Lab Results:
- HbA1c: 9.2% (HIGH)
- Fasting Glucose: 256 mg/dL
- Blood Pressure: 145/92 mmHg

Provider: Dr. Sarah Johnson, MD
Nurse: Patricia Brown, RN
Next appointment: 04/20/2025 at 2:30 PM
"""
    
    # Anonymize
    result = anonymizer("test_user", "TEST", test_text)
    anonymized_text = json.loads(result['body'])['result']
    
    print_result("Original", test_text)
    print_result("Anonymized", anonymized_text, highlight=True)
    
    # Check what should be preserved
    print(f"\n{BOLD}Checking Medical Information Preservation:{RESET}")
    passed = True
    
    # Medical information that should be preserved
    medical_terms = [
        ("Type 2 Diabetes", "Diagnosis"),
        ("E11.9", "ICD Code"),
        ("Hypertension", "Diagnosis"),
        ("I10", "ICD Code"),
        ("Metformin 1000mg BID", "Medication"),
        ("Lisinopril 20mg daily", "Medication"),
        ("Insulin Glargine 24 units", "Medication"),
        ("HbA1c: 9.2%", "Lab Value"),
        ("Glucose: 256 mg/dL", "Lab Value"),
        ("145/92 mmHg", "Blood Pressure"),
        ("Dr. Sarah Johnson", "Provider Name"),
        ("Patricia Brown, RN", "Nurse Name")
    ]
    
    for term, desc in medical_terms:
        if term in anonymized_text:
            print(f"{GREEN}✓ {desc} preserved: {term}{RESET}")
        else:
            print(f"{RED}✗ {desc} was removed/changed: {term}{RESET}")
            passed = False
    
    # Check what should be anonymized
    print(f"\n{BOLD}Checking HIPAA Identifier Anonymization:{RESET}")
    
    pii_terms = [
        ("John Smith", "Patient Name"),
        ("03/15/1975", "Date of Birth"),
        ("ABC-123456", "MRN"),
        ("555-123-4567", "Phone"),
        ("jsmith@email.com", "Email"),
        ("123-45-6789", "SSN"),
        ("BCB987654321", "Insurance ID"),
        ("04/20/2025", "Appointment Date")
    ]
    
    for term, desc in pii_terms:
        if term not in anonymized_text:
            print(f"{GREEN}✓ {desc} anonymized (removed): {term}{RESET}")
        else:
            print(f"{RED}✗ {desc} not anonymized: {term}{RESET}")
            passed = False
    
    # Test de-anonymization
    print(f"\n{BOLD}Testing De-anonymization:{RESET}")
    de_result = de_anonymizer("test_user", "TEST", anonymized_text)
    restored_text = json.loads(de_result['body'])['result']
    
    if restored_text == test_text:
        print(f"{GREEN}✓ De-anonymization successful - original text restored{RESET}")
    else:
        print(f"{RED}✗ De-anonymization failed - text not fully restored{RESET}")
        passed = False
    
    return passed

def test_json_anonymization():
    """Test JSON anonymization"""
    print_test_header("JSON Anonymization - Patient Record")
    
    test_json = {
        "patient": {
            "name": "Jane Doe",
            "dob": "01/15/1960",
            "mrn": "MRN-789456",
            "phone": "555-987-6543",
            "email": "jane.doe@email.com"
        },
        "visit_info": {
            "date": "03/15/2025",
            "provider": "Dr. Michael Chen, MD",
            "nurse": "Susan Williams, RN"
        },
        "diagnoses": [
            "Type 2 Diabetes Mellitus (E11.9)",
            "Essential Hypertension (I10)",
            "Hyperlipidemia (E78.5)"
        ],
        "medications": [
            {
                "name": "Metformin",
                "dose": "1000mg",
                "frequency": "BID"
            },
            {
                "name": "Atorvastatin",
                "dose": "40mg",
                "frequency": "Daily"
            }
        ],
        "vitals": {
            "blood_pressure": "138/88",
            "heart_rate": 76,
            "temperature": 98.4
        },
        "lab_results": {
            "hba1c": 7.8,
            "ldl": 145,
            "hdl": 42,
            "triglycerides": 185
        }
    }
    
    # Anonymize
    result = anonymize_json("test_user", "TEST", test_json)
    anonymized = json.loads(result['body'])['result']
    
    print_result("Original JSON", json.dumps(test_json, indent=2))
    print_result("Anonymized JSON", json.dumps(anonymized, indent=2), highlight=True)
    
    passed = True
    
    # Check medical information preservation
    print(f"\n{BOLD}Checking Medical Information Preservation in JSON:{RESET}")
    
    # Check diagnoses preserved
    for i, diagnosis in enumerate(test_json['diagnoses']):
        if anonymized['diagnoses'][i] == diagnosis:
            print(f"{GREEN}✓ Diagnosis preserved: {diagnosis}{RESET}")
        else:
            print(f"{RED}✗ Diagnosis changed: {diagnosis}{RESET}")
            passed = False
    
    # Check medications preserved
    for i, med in enumerate(test_json['medications']):
        anon_med = anonymized['medications'][i]
        if (anon_med['name'] == med['name'] and 
            anon_med['dose'] == med['dose'] and 
            anon_med['frequency'] == med['frequency']):
            print(f"{GREEN}✓ Medication preserved: {med['name']} {med['dose']} {med['frequency']}{RESET}")
        else:
            print(f"{RED}✗ Medication changed{RESET}")
            passed = False
    
    # Check vitals preserved
    if (anonymized['vitals']['blood_pressure'] == test_json['vitals']['blood_pressure'] and
        anonymized['vitals']['heart_rate'] == test_json['vitals']['heart_rate']):
        print(f"{GREEN}✓ Vitals preserved{RESET}")
    else:
        print(f"{RED}✗ Vitals changed{RESET}")
        passed = False
    
    # Check lab results preserved
    if anonymized['lab_results'] == test_json['lab_results']:
        print(f"{GREEN}✓ Lab results preserved{RESET}")
    else:
        print(f"{RED}✗ Lab results changed{RESET}")
        passed = False
    
    # Check provider names preserved
    if (anonymized['visit_info']['provider'] == test_json['visit_info']['provider'] and
        anonymized['visit_info']['nurse'] == test_json['visit_info']['nurse']):
        print(f"{GREEN}✓ Provider names preserved{RESET}")
    else:
        print(f"{RED}✗ Provider names changed{RESET}")
        passed = False
    
    # Check PII anonymization
    print(f"\n{BOLD}Checking PII Anonymization in JSON:{RESET}")
    
    if anonymized['patient']['name'] != test_json['patient']['name']:
        print(f"{GREEN}✓ Patient name anonymized{RESET}")
    else:
        print(f"{RED}✗ Patient name not anonymized{RESET}")
        passed = False
    
    if anonymized['patient']['mrn'] != test_json['patient']['mrn']:
        print(f"{GREEN}✓ MRN anonymized{RESET}")
    else:
        print(f"{RED}✗ MRN not anonymized{RESET}")
        passed = False
    
    # Test de-anonymization
    print(f"\n{BOLD}Testing JSON De-anonymization:{RESET}")
    de_result = de_anonymize_json("test_user", "TEST", anonymized)
    restored = json.loads(de_result['body'])['result']
    
    if restored == test_json:
        print(f"{GREEN}✓ JSON de-anonymization successful{RESET}")
    else:
        print(f"{RED}✗ JSON de-anonymization failed{RESET}")
        passed = False
    
    return passed

def test_edge_cases():
    """Test edge cases and special scenarios"""
    print_test_header("Edge Cases and Special Scenarios")
    
    passed = True
    
    # Test 1: Provider names should not be anonymized
    print(f"{BOLD}Test 1: Provider Name Preservation{RESET}")
    text1 = "Patient seen by Dr. John Smith. Referring physician: Dr. Jane Doe, MD."
    result1 = anonymizer("test_user", "TEST", text1)
    anon1 = json.loads(result1['body'])['result']
    
    if "Dr. John Smith" in anon1 and "Dr. Jane Doe, MD" in anon1:
        print(f"{GREEN}✓ Provider names preserved correctly{RESET}")
    else:
        print(f"{RED}✗ Provider names were anonymized{RESET}")
        passed = False
    
    # Test 2: Patient names should be anonymized
    print(f"\n{BOLD}Test 2: Patient Name Anonymization{RESET}")
    text2 = "Patient: John Smith was seen today. His mother Mary Smith was present."
    result2 = anonymizer("test_user", "TEST", text2)
    anon2 = json.loads(result2['body'])['result']
    
    if "John Smith" not in anon2 and "Mary Smith" not in anon2:
        print(f"{GREEN}✓ Patient and family names anonymized{RESET}")
    else:
        print(f"{RED}✗ Patient/family names not properly anonymized{RESET}")
        passed = False
    
    # Test 3: ZIP code handling
    print(f"\n{BOLD}Test 3: ZIP Code Special Handling{RESET}")
    text3 = "Address: 123 Main St, City, State 03698"  # Restricted ZIP
    result3 = anonymizer("test_user", "TEST", text3)
    anon3 = json.loads(result3['body'])['result']
    
    if "00000" in anon3 or "036**" in anon3:
        print(f"{GREEN}✓ Restricted ZIP code handled correctly{RESET}")
    else:
        print(f"{RED}✗ Restricted ZIP code not handled properly{RESET}")
        passed = False
    
    # Test 4: Complex medical content
    print(f"\n{BOLD}Test 4: Complex Medical Content Preservation{RESET}")
    text4 = """
    Neuropsychiatric Inventory Results:
    - MMSE Score: 24/30
    - MoCA Score: 22/30
    - Clock Drawing: Mild impairment
    - Anxiety Score: 2, Caregiver Distress: 3
    
    Brain MRI findings: Mild cerebral atrophy, scattered white matter hyperintensities
    
    Current medications:
    - Donepezil 10mg daily
    - Memantine 10mg BID
    - Sertraline 50mg daily
    """
    
    result4 = anonymizer("test_user", "TEST", text4)
    anon4 = json.loads(result4['body'])['result']
    
    medical_content = [
        "MMSE Score: 24/30",
        "MoCA Score: 22/30",
        "Mild cerebral atrophy",
        "Donepezil 10mg daily",
        "Anxiety Score: 2"
    ]
    
    all_preserved = True
    for content in medical_content:
        if content in anon4:
            print(f"{GREEN}✓ Medical content preserved: {content}{RESET}")
        else:
            print(f"{RED}✗ Medical content lost: {content}{RESET}")
            all_preserved = False
            passed = False
    
    return passed

def test_entity_detection():
    """Test that entity detection only identifies HIPAA identifiers"""
    print_test_header("Entity Detection - HIPAA Identifiers Only")
    
    test_text = """
    Patient: John Doe, MRN: 123456
    Diagnosis: Type 2 Diabetes, Hypertension
    Medications: Metformin 1000mg BID
    Provider: Dr. Sarah Johnson
    Lab: Glucose 156 mg/dL, HbA1c 8.2%
    """
    
    entities = detect_pii_data(test_text)
    
    print(f"{BOLD}Detected Entities:{RESET}")
    for entity in entities:
        print(f"  - Type: {entity['Type']}, Value: {entity['originalData']}")
    
    # Check that medical terms were NOT detected as entities
    medical_terms = ["Type 2 Diabetes", "Hypertension", "Metformin", "Glucose", "HbA1c"]
    passed = True
    
    detected_values = [e['originalData'] for e in entities]
    
    print(f"\n{BOLD}Verification:{RESET}")
    for term in medical_terms:
        if term not in detected_values:
            print(f"{GREEN}✓ Medical term '{term}' correctly NOT detected as PII{RESET}")
        else:
            print(f"{RED}✗ Medical term '{term}' incorrectly detected as PII{RESET}")
            passed = False
    
    # Check that PII WAS detected
    if any("John Doe" in e['originalData'] for e in entities):
        print(f"{GREEN}✓ Patient name correctly detected{RESET}")
    else:
        print(f"{RED}✗ Patient name not detected{RESET}")
        passed = False
    
    if any("123456" in e['originalData'] for e in entities):
        print(f"{GREEN}✓ MRN correctly detected{RESET}")
    else:
        print(f"{RED}✗ MRN not detected{RESET}")
        passed = False
    
    return passed

def run_all_tests():
    """Run all tests and report results"""
    print(f"\n{BOLD}{BLUE}{'='*60}{RESET}")
    print(f"{BOLD}{BLUE}HIPAA COMPLIANCE TEST SUITE{RESET}")
    print(f"{BOLD}{BLUE}Testing Medical Data Anonymizer{RESET}")
    print(f"{BOLD}{BLUE}{'='*60}{RESET}")
    
    tests = [
        ("Entity Detection", test_entity_detection),
        ("Text Anonymization", test_text_anonymization),
        ("JSON Anonymization", test_json_anonymization),
        ("Edge Cases", test_edge_cases)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            passed = test_func()
            results.append((test_name, passed))
        except Exception as e:
            print(f"{RED}Error in {test_name}: {str(e)}{RESET}")
            results.append((test_name, False))
    
    # Summary
    print(f"\n{BOLD}{BLUE}{'='*60}{RESET}")
    print(f"{BOLD}{BLUE}TEST SUMMARY{RESET}")
    print(f"{BOLD}{BLUE}{'='*60}{RESET}\n")
    
    total_tests = len(results)
    passed_tests = sum(1 for _, passed in results if passed)
    
    for test_name, passed in results:
        status = f"{GREEN}PASSED{RESET}" if passed else f"{RED}FAILED{RESET}"
        print(f"{test_name}: {status}")
    
    print(f"\n{BOLD}Total: {passed_tests}/{total_tests} tests passed{RESET}")
    
    if passed_tests == total_tests:
        print(f"\n{GREEN}{BOLD}✓ All tests passed! The anonymizer is HIPAA compliant.{RESET}")
        return 0
    else:
        print(f"\n{RED}{BOLD}✗ Some tests failed. Please review the implementation.{RESET}")
        return 1

if __name__ == "__main__":
    sys.exit(run_all_tests())
