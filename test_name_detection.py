#!/usr/bin/env python3
"""
Test script to verify name detection fixes
Specifically tests "Mrs. Johnson" and "Sarah Johnson" cases
"""

import json
from comprehend import detect_pii_data
from anonymizer import anonymizer, anonymize_json

# Test case 1: Mrs. Johnson in conversation
print("=" * 60)
print("TEST 1: Mrs. Johnson in conversation")
print("=" * 60)

text1 = """Doctor: Hello Mrs. Johnson, how are you feeling today?
Patient: Not great, my blood sugar has been running high, around 250-300.
Doctor: I see. Are you taking your Metformin regularly?
Patient: Yes, 1000mg twice daily as prescribed.
Doctor: Let's check your A1C. Also, we'll schedule you for a follow-up on April 20th."""

print("Original text:")
print(text1)
print("\nDetecting entities...")

entities = detect_pii_data(text1)
print(f"\nFound {len(entities)} entities:")
for entity in entities:
    print(f"  - Type: {entity['Type']}, Value: '{entity['originalData']}'")

# Check if Mrs. Johnson was detected
mrs_johnson_found = any("Mrs. Johnson" in e['originalData'] or "Johnson" in e['originalData'] for e in entities)
print(f"\n{'✓' if mrs_johnson_found else '✗'} Mrs. Johnson detection: {'FOUND' if mrs_johnson_found else 'NOT FOUND'}")

# Test anonymization
result = anonymizer("test_user", "TEST", text1)
anonymized = json.loads(result['body'])['result']
print("\nAnonymized text:")
print(anonymized)

# Verify Mrs. Johnson was anonymized
if "Mrs. Johnson" not in anonymized and "Johnson" not in anonymized:
    print("\n✓ Mrs. Johnson was successfully anonymized")
else:
    print("\n✗ Mrs. Johnson was NOT anonymized")

# Test case 2: Sarah Johnson in JSON
print("\n" + "=" * 60)
print("TEST 2: Sarah Johnson in JSON")
print("=" * 60)

json_data = {
    "patient_info": {
        "name": "Sarah Johnson",
        "mrn": "MRN-789456"
    },
    "diagnosis": "Type 2 Diabetes",
    "provider": "Dr. Emily Watson"
}

print("Original JSON:")
print(json.dumps(json_data, indent=2))

# Test JSON anonymization
result = anonymize_json("test_user", "TEST", json_data)
anonymized_json = json.loads(result['body'])['result']

print("\nAnonymized JSON:")
print(json.dumps(anonymized_json, indent=2))

# Verify Sarah Johnson was anonymized
if anonymized_json['patient_info']['name'] != "Sarah Johnson":
    print(f"\n✓ Sarah Johnson was successfully anonymized to: {anonymized_json['patient_info']['name']}")
else:
    print("\n✗ Sarah Johnson was NOT anonymized")

# Verify provider name was NOT anonymized
if anonymized_json.get('provider') == "Dr. Emily Watson":
    print("✓ Provider name (Dr. Emily Watson) was correctly preserved")
else:
    print("✗ Provider name was incorrectly anonymized")

# Test case 3: Edge cases
print("\n" + "=" * 60)
print("TEST 3: Edge cases")
print("=" * 60)

edge_cases = [
    "Mr. Smith has diabetes",
    "Ms. Davis called about her prescription",
    "The patient Johnson needs a refill",
    "Hello Anderson, your appointment is confirmed",
    "Mrs. Williams, Dr. Brown will see you now"
]

for text in edge_cases:
    entities = detect_pii_data(text)
    names_found = [e['originalData'] for e in entities if e['Type'] == 'NAME']
    print(f"\nText: '{text}'")
    print(f"Names detected: {names_found if names_found else 'None'}")
    
    # Check if provider names were excluded
    if "Dr. Brown" in text and "Dr. Brown" not in str(names_found):
        print("  ✓ Provider name correctly excluded")

print("\n" + "=" * 60)
print("TEST COMPLETE")
print("=" * 60)
