"""
Simple Chat Application for Testing Medical Data Anonymizer
Run with: python chat_app.py
Access at: http://localhost:5000
"""

from flask import Flask, render_template_string, request, jsonify, session
import json
import uuid
import os
from datetime import datetime,timezone

from collections import OrderedDict
from dotenv import load_dotenv
from presidio_analyzer import AnalyzerEngine
from faker import Faker
from faker.providers import BaseProvider
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
# Load environment variables
load_dotenv()

# Import your anonymizer modules
from anonymizer import (anonymizer, de_anonymizer, anonymize_profile, 
                       de_anonymize_profile, anonymize_json, de_anonymize_json)
from comprehend import detect_pii_data
from db_methods import get_anonymization_statistics

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', os.urandom(24))

@app.route('/')
def health_check():
    return jsonify({
        "status": "healthy",
        "service": "anonymizer-api",
        "version": "1.0.0",
        "endpoints": [
            "/anonymize",
            "/deanonymize",
            "/anonymize_json",
            "/deanonymize_json",
            "/detect",
            "/stats"
        ]
    })

# HTML Template
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Medical Data Anonymizer Test Chat</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }
        .chat-box {
            background: white;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .chat-messages {
            height: 400px;
            overflow-y: auto;
            border: 1px solid #ddd;
            padding: 10px;
            margin-bottom: 10px;
            background: #fafafa;
        }
        .message {
            margin: 10px 0;
            padding: 10px;
            border-radius: 5px;
        }
        .original {
            background: #e3f2fd;
            border-left: 4px solid #2196F3;
        }
        .anonymized {
            background: #e8f5e9;
            border-left: 4px solid #4CAF50;
        }
        .entities {
            background: #fff3e0;
            border-left: 4px solid #FF9800;
            font-size: 12px;
        }
        textarea {
            width: 100%;
            height: 100px;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            resize: vertical;
        }
        button {
            background: #2196F3;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 4px;
            cursor: pointer;
            margin: 5px;
        }
        button:hover {
            background: #1976D2;
        }
        .stats {
            background: #f5f5f5;
            padding: 10px;
            border-radius: 4px;
            margin-top: 10px;
            font-size: 14px;
        }
        .examples {
            margin-top: 20px;
            padding: 15px;
            background: #e8eaf6;
            border-radius: 4px;
        }
        .example-btn {
            background: #673AB7;
            font-size: 12px;
            padding: 5px 10px;
            margin: 2px;
        }
        .json-btn {
            background: #FF5722;
        }
        .error {
            color: #d32f2f;
            background: #ffebee;
            padding: 10px;
            border-radius: 4px;
            margin: 10px 0;
        }
        .success {
            color: #388E3C;
            background: #e8f5e9;
            padding: 10px;
            border-radius: 4px;
            margin: 10px 0;
        }
        h3 {
            margin-top: 0;
            color: #333;
        }
        .entity-tag {
            display: inline-block;
            background: #FF9800;
            color: white;
            padding: 2px 8px;
            border-radius: 3px;
            margin: 2px;
            font-size: 11px;
        }
        pre {
            background: #f5f5f5;
            padding: 10px;
            border-radius: 4px;
            overflow-x: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        .info-box {
            background: #e3f2fd;
            border: 1px solid #2196F3;
            padding: 15px;
            border-radius: 4px;
            margin-bottom: 20px;
        }
        .info-box h4 {
            margin-top: 0;
            color: #1976D2;
        }
        .preserved {
            color: #4CAF50;
            font-weight: bold;
        }
        .anonymized-item {
            color: #FF5722;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <h1>Medical Data Anonymizer Test Chat</h1>
    
    <div class="info-box">
        <h4>HIPAA Safe Harbor Anonymization</h4>
        <p><span class="anonymized-item">Anonymizes:</span> Names, addresses, dates, phone numbers, emails, SSN, MRN, insurance IDs, and other personal identifiers</p>
        <p><span class="preserved">Preserves:</span> Diagnoses, medications, lab values, clinical observations, assessment scores, and all medical information</p>
        <p><strong>Note:</strong> Healthcare provider names (Dr., Nurse, etc.) are NOT anonymized</p>
    </div>
    
    <div class="container">
        <div class="chat-box">
            <h3>Original Text</h3>
            <div id="original-messages" class="chat-messages"></div>
            
            <h3>Input Medical Data</h3>
            <textarea id="chat-input" placeholder="Enter patient data, clinical notes, conversations, or JSON..."></textarea>
            
            <div>
                <button onclick="anonymizeText()">Anonymize Text</button>
                <button onclick="anonymizeJSON()">Anonymize JSON</button>
                <button onclick="detectEntities()">Detect Entities Only</button>
                <button onclick="clearChat()">Clear</button>
            </div>
            
            <div class="stats" id="stats"></div>
        </div>
        
        <div class="chat-box">
            <h3>Anonymized Text</h3>
            <div id="anonymized-messages" class="chat-messages"></div>
            
            <h3>Actions</h3>
            <button onclick="deAnonymizeLastMessage()">De-Anonymize Last</button>
            <button onclick="deAnonymizeLastJSON()">De-Anonymize JSON</button>
            <button onclick="showStats()">Show Statistics</button>
            
            <div id="entity-display"></div>
        </div>
    </div>
    
    <div class="examples">
        <h3>Test Examples (Click to Load)</h3>
        <button class="example-btn" onclick="loadExample('clinical')">Clinical Note</button>
        <button class="example-btn" onclick="loadExample('medications')">Medications</button>
        <button class="example-btn" onclick="loadExample('labs')">Lab Results</button>
        <button class="example-btn" onclick="loadExample('provider')">With Provider Names</button>
        <button class="example-btn" onclick="loadExample('conversation')">Patient Conversation</button>
        <button class="example-btn" onclick="loadExample('profile')">Patient Profile</button>
        <button class="example-btn json-btn" onclick="loadExample('json_example')">JSON Example</button>
        <button class="example-btn json-btn" onclick="loadExample('json_medical')">JSON Medical Data</button>
        <button class="example-btn json-btn" onclick="loadExample('neuropsych')">Neuropsychiatric Inventory</button>
    </div>
    
    <script>
        let lastAnonymizedText = '';
        let lastWasJSON = false;
        
        // Custom JSON parser that preserves order
        function parseJSON(jsonString) {
            try {
                // Basic JSON parse - in production you'd want a proper order-preserving parser
                return JSON.parse(jsonString);
            } catch (e) {
                throw e;
            }
        }
        
        // Custom JSON stringifier that preserves order
        function stringifyJSON(obj, indent = 2) {
            // This maintains the order as much as possible
            return JSON.stringify(obj, null, indent);
        }
        
        async function anonymizeText() {
            const input = document.getElementById('chat-input').value;
            if (!input.trim()) return;
            
            try {
                const response = await fetch('/anonymize', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({text: input})
                });
                
                const data = await response.json();
                
                if (data.error) {
                    showError(data.error);
                    return;
                }
                
                // Display original
                addMessage('original-messages', input, 'original');
                
                // Display anonymized
                addMessage('anonymized-messages', data.anonymized, 'anonymized');
                lastAnonymizedText = data.anonymized;
                lastWasJSON = false;
                
                // Display entities
                displayEntities(data.entities);
                
                // Update stats
                updateStats(data.stats);
                
                // Clear input
                document.getElementById('chat-input').value = '';
                
            } catch (error) {
                showError('Error: ' + error.message);
            }
        }
        
        async function anonymizeJSON() {
            const input = document.getElementById('chat-input').value;
            if (!input.trim()) return;
            
            try {
                // Try to parse as JSON, with better error handling
                let jsonData;
                try {
                    // First, try to fix common JSON issues
                    let fixedInput = input.trim();
                    
                    // Check if JSON is incomplete (common copy-paste issue)
                    // Count opening and closing braces/brackets
                    const openBraces = (fixedInput.match(/{/g) || []).length;
                    const closeBraces = (fixedInput.match(/}/g) || []).length;
                    const openBrackets = (fixedInput.match(/\\[/g) || []).length;
                    const closeBrackets = (fixedInput.match(/\\]/g) || []).length;
                    
                    // Add missing closing braces/brackets
                    if (openBraces > closeBraces) {
                        fixedInput += '}'.repeat(openBraces - closeBraces);
                    }
                    if (openBrackets > closeBrackets) {
                        fixedInput += ']'.repeat(openBrackets - closeBrackets);
                    }
                    
                    // If the JSON ends with a comma or incomplete value, try to fix it
                    if (fixedInput.endsWith(',"') || fixedInput.endsWith(':"')) {
                        fixedInput = fixedInput.slice(0, -1) + '}';
                    } else if (fixedInput.endsWith('"')) {
                        // Check if this is an incomplete value
                        const lastColon = fixedInput.lastIndexOf('":');
                        if (lastColon > fixedInput.lastIndexOf('}')) {
                            // This looks like an incomplete value
                            fixedInput += '"}';
                        }
                    }
                    
                    jsonData = parseJSON(fixedInput);
                    
                    // If we had to fix the JSON, show a warning
                    if (fixedInput !== input.trim()) {
                        showWarning('JSON was incomplete. Auto-completed for processing.');
                    }
                    
                } catch (e) {
                    showError('Invalid JSON format: ' + e.message + '\\n\\nPlease check your JSON syntax.');
                    return;
                }
                
                const response = await fetch('/anonymize_json', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({json_data: jsonData})
                });
                
                const data = await response.json();
                
                if (data.error) {
                    showError(data.error);
                    return;
                }
                
                // Display original with preserved formatting
                const originalFormatted = stringifyJSON(jsonData);
                addMessage('original-messages', '<pre>' + originalFormatted + '</pre>', 'original');
                
                // Display anonymized with preserved formatting
                const anonymizedFormatted = stringifyJSON(data.anonymized);
                addMessage('anonymized-messages', '<pre>' + anonymizedFormatted + '</pre>', 'anonymized');
                lastAnonymizedText = data.anonymized;
                lastWasJSON = true;
                
                // Update stats
                updateStats(data.stats);
                
                // Display message about what was anonymized
                if (data.entities_detected === 0) {
                    showInfo('No personal identifiers were detected. Medical information is preserved.');
                } else {
                    showSuccess(`Successfully anonymized ${data.entities_detected} personal identifiers. All medical information preserved.`);
                }
                
                // Clear input
                document.getElementById('chat-input').value = '';
                
            } catch (error) {
                showError('Error: ' + error.message);
            }
        }
        
        function showWarning(message) {
            const display = document.getElementById('entity-display');
            display.innerHTML = `<div class="entities" style="background: #fff3e0; border-left-color: #FF9800;">${message}</div>`;
        }
        
        function showSuccess(message) {
            const display = document.getElementById('entity-display');
            display.innerHTML = `<div class="success">${message}</div>`;
        }
        
        function showInfo(message) {
            const display = document.getElementById('entity-display');
            display.innerHTML = `<div class="entities" style="background: #e3f2fd; border-left-color: #2196F3;">${message}</div>`;
        }
        
        async function detectEntities() {
            const input = document.getElementById('chat-input').value;
            if (!input.trim()) return;
            
            try {
                const response = await fetch('/detect', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({text: input})
                });
                
                const data = await response.json();
                displayEntities(data.entities);
                
            } catch (error) {
                showError('Error: ' + error.message);
            }
        }
        
        async function deAnonymizeLastMessage() {
            if (!lastAnonymizedText) {
                showError('No anonymized text to de-anonymize');
                return;
            }
            
            if (lastWasJSON) {
                deAnonymizeLastJSON();
                return;
            }
            
            try {
                const response = await fetch('/deanonymize', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({text: lastAnonymizedText})
                });
                
                const data = await response.json();
                
                if (data.error) {
                    showError(data.error);
                    return;
                }
                
                addMessage('anonymized-messages', 
                    '<strong>De-Anonymized:</strong><br>' + data.deanonymized, 
                    'original');
                
            } catch (error) {
                showError('Error: ' + error.message);
            }
        }
        
        async function deAnonymizeLastJSON() {
            if (!lastAnonymizedText || !lastWasJSON) {
                showError('No anonymized JSON to de-anonymize');
                return;
            }
            
            try {
                const response = await fetch('/deanonymize_json', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({json_data: lastAnonymizedText})
                });
                
                const data = await response.json();
                
                if (data.error) {
                    showError(data.error);
                    return;
                }
                
                const deanonymizedFormatted = stringifyJSON(data.deanonymized);
                addMessage('anonymized-messages', 
                    '<strong>De-Anonymized JSON:</strong><br><pre>' + deanonymizedFormatted + '</pre>', 
                    'original');
                
                if (data.entities_restored > 0) {
                    showSuccess(`Successfully restored ${data.entities_restored} personal identifiers.`);
                } else {
                    showWarning('No entities were restored.');
                }
                
            } catch (error) {
                showError('Error: ' + error.message);
            }
        }
        
        function addMessage(containerId, text, className) {
            const container = document.getElementById(containerId);
            const message = document.createElement('div');
            message.className = 'message ' + className;
            message.innerHTML = text.replace(/\\n/g, '<br>');
            container.appendChild(message);
            container.scrollTop = container.scrollHeight;
        }
        
        function displayEntities(entities) {
            const display = document.getElementById('entity-display');
            if (!entities || entities.length === 0) {
                display.innerHTML = '<div class="entities">No personal identifiers detected. Medical information preserved.</div>';
                return;
            }
            
            const entityTypes = {};
            entities.forEach(e => {
                if (!entityTypes[e.Type]) entityTypes[e.Type] = [];
                entityTypes[e.Type].push(e.originalData);
            });
            
            let html = '<div class="entities"><strong>Detected Personal Identifiers (to be anonymized):</strong><br>';
            for (const [type, values] of Object.entries(entityTypes)) {
                html += `<div style="margin: 5px 0;">`;
                html += `<strong>${type}:</strong> `;
                values.forEach(v => {
                    html += `<span class="entity-tag">${v}</span>`;
                });
                html += '</div>';
            }
            html += '</div>';
            display.innerHTML = html;
        }
        
        function updateStats(stats) {
            if (!stats) return;
            const statsDiv = document.getElementById('stats');
            statsDiv.innerHTML = `
                <strong>Statistics:</strong><br>
                Personal Identifiers Detected: ${stats.entities_detected}<br>
                Compliance: HIPAA ${stats.hipaa_compliant ? '✓' : '✗'}, 
                GDPR ${stats.gdpr_compliant ? '✓' : '✗'}
                ${stats.structure_preserved ? '<br>Structure Preserved: ✓' : ''}
            `;
        }
        
        async function showStats() {
            try {
                const response = await fetch('/stats');
                const data = await response.json();
                
                let html = '<div class="success"><strong>Anonymization Statistics:</strong><br>';
                html += `Total Entities: ${data.total_entities}<br>`;
                html += `HIPAA Identifiers: ${data.hipaa_entities || data.total_entities}<br>`;
                
                if (data.summary) {
                    html += '<br><strong>Operations Summary:</strong><br>';
                    html += `Total Anonymizations: ${data.summary.anonymizations}<br>`;
                    html += `Total De-anonymizations: ${data.summary.de_anonymizations}<br>`;
                    html += `Unique Entity Types: ${data.summary.unique_entity_types}<br>`;
                }
                
                html += '<br><strong>By Type:</strong><br>';
                if (data.entity_types && Object.keys(data.entity_types).length > 0) {
                    for (const [type, count] of Object.entries(data.entity_types)) {
                        html += `${type}: ${count}<br>`;
                    }
                } else {
                    html += 'No entities recorded yet<br>';
                }
                
                if (data.operations && Object.keys(data.operations).length > 0) {
                    html += '<br><strong>Operations:</strong><br>';
                    for (const [method, count] of Object.entries(data.operations)) {
                        html += `${method}: ${count}<br>`;
                    }
                }
                
                html += '</div>';
                
                document.getElementById('entity-display').innerHTML = html;
                
            } catch (error) {
                showError('Error: ' + error.message);
            }
        }
        
        function clearChat() {
            document.getElementById('original-messages').innerHTML = '';
            document.getElementById('anonymized-messages').innerHTML = '';
            document.getElementById('entity-display').innerHTML = '';
            document.getElementById('stats').innerHTML = '';
            lastAnonymizedText = '';
            lastWasJSON = false;
        }
        
        function showError(message) {
            const display = document.getElementById('entity-display');
            display.innerHTML = `<div class="error">${message}</div>`;
        }
        
        function loadExample(type) {
            const examples = {
                clinical: `Patient: John Smith, MRN: ABC-123-456789
DOB: 03/15/1975, Phone: 555-123-4567
Diagnosis: Type 2 Diabetes (ICD-10: E11.9)
Medications: Metformin 1000mg BID, Lisinopril 10mg daily
Latest A1C: 8.5%, Glucose: 245 mg/dL
Next appointment: 04/15/2025 at 2:30 PM`,
                
                medications: `Current Medications:
1. Metformin 1000mg PO BID with meals
2. Insulin Glargine 24 units subcutaneous at bedtime
3. Lisinopril 10mg daily for hypertension
4. Gabapentin 300mg TID for neuropathy
PRN: Albuterol inhaler 2 puffs q4h as needed`,
                
                labs: `Lab Results from 03/20/2025:
Glucose: 320 mg/dL (HIGH)
A1C: 11.2%
Creatinine: 2.1 mg/dL
Blood pressure: 165/102 mmHg
Temperature: 101.5°F`,
                
                provider: `Patient: Jane Doe seen by Dr. Michael Chen
Referring physician: Dr. Sarah Williams
Consulting psychiatrist: Dr. Robert Johnson
Primary nurse: Nurse Patricia Brown RN
Care coordinator: Mary Thompson
Insurance: Blue Cross Blue Shield`,
                
                conversation: `Doctor: Hello Mrs. Johnson, how are you feeling today?
Patient: Not great, my blood sugar has been running high, around 250-300.
Doctor: I see. Are you taking your Metformin regularly?
Patient: Yes, 1000mg twice daily as prescribed.
Doctor: Let's check your A1C. Also, we'll schedule you for a follow-up on April 20th.`,
                
                profile: `Name: Jane Doe
DOB: 01/15/1960
Phone: 555-987-6543
Address: 123 Main St, Boston, MA 02101
Insurance ID: BCB123456789
Diagnosis: Hypertension, Type 2 Diabetes
Medications: Metoprolol 50mg daily, Metformin 500mg BID`,
                
                json_example: `{
  "patient": {
    "name": "Sarah Johnson",
    "dob": "15/03/1975",
    "mrn": "MRN-789456"
  },
  "diagnosis": "Mild Cognitive Impairment (F06.7)",
  "medications": ["Donepezil 5mg daily", "Memantine 10mg BID"],
  "referral_info": {
    "clinic_name": "Brain Health Clinic",
    "referral_reason": "memory concerns",
    "referring_provider": "Dr. Michael Chen",
    "referral_date": "19/Nov/2024"
  },
  "assessment_info": {
    "date": "19/Nov/2024",
    "provider": "Dr. Emily Watson",
    "next_appointment": "15/Jan/2025"
  }
}`,
                
                json_medical: `{
  "patient_id": "PT-123456",
  "visit_date": "2025-01-15",
  "vitals": {
    "blood_pressure": "140/90",
    "heart_rate": 78,
    "temperature": 98.6,
    "oxygen_saturation": 96
  },
  "diagnoses": [
    "Essential Hypertension (I10)",
    "Type 2 Diabetes Mellitus (E11.9)",
    "Hyperlipidemia (E78.5)"
  ],
  "medications": [
    {
      "name": "Metformin",
      "dose": "1000mg",
      "frequency": "BID",
      "route": "PO"
    },
    {
      "name": "Lisinopril",
      "dose": "20mg",
      "frequency": "Daily",
      "route": "PO"
    }
  ],
  "lab_results": {
    "hba1c": 7.8,
    "glucose_fasting": 156,
    "ldl_cholesterol": 145,
    "hdl_cholesterol": 38,
    "triglycerides": 220
  }
}`,

                neuropsych: `{
  "patient_info": {
    "name": "Sarah Johnson",
    "mrn": "MRN-789456"
  },
  "neuropsychiatric_inventory": {
    "apathy": {
      "score": 2,
      "caregiver_distress": 2
    },
    "anxiety": {
      "score": 1,
      "caregiver_distress": 1
    },
    "depression": {
      "score": 2,
      "caregiver_distress": 3
    }
  },
  "cognitive_assessment": {
    "mmse_score": 24,
    "moca_score": 22,
    "clock_drawing": "mild impairment"
  },
  "clinical_observations": [
    "no signs of mood disorders or psychosis",
    "speech was normal",
    "good insight into condition",
    "fully alert and responsive",
    "normal facial and hand movements",
    "no tremors observed",
    "mood was reportedly stable",
    "occasionally struggled to find the correct words"
  ],
  "medications": [
    "Donepezil 10mg daily",
    "Memantine 10mg BID",
    "Citalopram 20mg daily"
  ]
}`
            };
            
            document.getElementById('chat-input').value = examples[type] || '';
        }
    </script>
</body>
</html>
'''

# Routes
@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/anonymize', methods=['POST'])
def anonymize_endpoint():
    try:
        data = request.get_json()
        text = data.get('text', '')
        
        # Use a session ID as identity
        if 'user_id' not in session:
            session['user_id'] = str(uuid.uuid4())
        
        # Call anonymizer
        context = {
            'purpose': 'testing',
            'user_id': 'test_user',
            'timestamp': datetime.utcnow().isoformat()
        }
        
        result = anonymizer(
            session['user_id'],
            'SESSION_ID',
            text,
            context
        )
        
        if result['statusCode'] != 200:
            return jsonify({'error': result.get('error', 'Unknown error')}), 500
        
        body = json.loads(result['body'])
        
        # Also get the detected entities
        entities = detect_pii_data(text)
        
        return jsonify({
            'anonymized': body['result'],
            'entities': entities,
            'stats': {
                'entities_detected': body.get('entities_detected', 0),
                'hipaa_compliant': body.get('compliance', {}).get('hipaa_safe_harbor', False),
                'gdpr_compliant': body.get('compliance', {}).get('gdpr_pseudonymized', False)
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/deanonymize', methods=['POST'])
def deanonymize_endpoint():
    try:
        data = request.get_json()
        text = data.get('text', '')
        
        if 'user_id' not in session:
            return jsonify({'error': 'No session found'}), 400
        
        context = {
            'access_reason': 'testing',
            'authorized_by': 'test_user'
        }
        
        result = de_anonymizer(
            session['user_id'],
            'SESSION_ID',
            text,
            context
        )
        
        if result['statusCode'] != 200:
            return jsonify({'error': result.get('error', 'Unknown error')}), 500
        
        body = json.loads(result['body'])
        
        return jsonify({
            'deanonymized': body['result'],
            'entities_restored': body.get('entities_restored', 0)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/anonymize_json', methods=['POST'])
def anonymize_json_endpoint():
    try:
        data = request.get_json()
        json_data = data.get('json_data', {})
        
        # Use a session ID as identity
        if 'user_id' not in session:
            session['user_id'] = str(uuid.uuid4())
        
        # Call JSON anonymizer
        context = {
            'purpose': 'testing',
            'user_id': 'test_user',
            'timestamp': datetime.utcnow().isoformat()
        }
        
        result = anonymize_json(
            session['user_id'],
            'SESSION_ID',
            json_data,
            context
        )
        
        if result['statusCode'] != 200:
            return jsonify({'error': result.get('error', 'Unknown error')}), 500
        
        # Parse the body preserving order
        body = json.loads(result['body'], object_pairs_hook=OrderedDict)
        
        # Return response preserving order
        response = {
            'anonymized': body['result'],
            'entities_detected': body.get('entities_detected', 0),
            'stats': {
                'entities_detected': body.get('entities_detected', 0),
                'hipaa_compliant': body.get('compliance', {}).get('hipaa_safe_harbor', False),
                'gdpr_compliant': body.get('compliance', {}).get('gdpr_pseudonymized', False),
                'structure_preserved': body.get('compliance', {}).get('structure_preserved', False)
            }
        }
        
        # Use Flask's jsonify with custom JSON encoder to preserve order
        return app.response_class(
            response=json.dumps(response, sort_keys=False),
            status=200,
            mimetype='application/json'
        )
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/deanonymize_json', methods=['POST'])
def deanonymize_json_endpoint():
    try:
        data = request.get_json()
        json_data = data.get('json_data', {})
        
        if 'user_id' not in session:
            return jsonify({'error': 'No session found'}), 400
        
        context = {
            'access_reason': 'testing',
            'authorized_by': 'test_user'
        }
        
        result = de_anonymize_json(
            session['user_id'],
            'SESSION_ID',
            json_data,
            context
        )
        
        if result['statusCode'] != 200:
            return jsonify({'error': result.get('error', 'Unknown error')}), 500
        
        # Parse the body preserving order
        body = json.loads(result['body'], object_pairs_hook=OrderedDict)
        
        # Return response preserving order
        response = {
            'deanonymized': body['result'],
            'entities_restored': body.get('entities_restored', 0)
        }
        
        # Use Flask's jsonify with custom JSON encoder to preserve order
        return app.response_class(
            response=json.dumps(response, sort_keys=False),
            status=200,
            mimetype='application/json'
        )
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/detect', methods=['POST'])
def detect_endpoint():
    try:
        data = request.get_json()
        text = data.get('text', '')
        
        entities = detect_pii_data(text)
        
        return jsonify({'entities': entities})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/stats', methods=['GET'])
def stats_endpoint():
    try:
        if 'user_id' in session:
            stats = get_anonymization_statistics(session['user_id'])
        else:
            stats = get_anonymization_statistics()
        
        return jsonify(stats)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Configuration constants
SESSIONS_FILE = "all_sessions.json"
SUPPORTED_ENTITIES = {
    "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", 
    "ADDRESS", "ZIP", "ORGANIZATION", "LOCATION"
}

@dataclass
class SessionData:
    """Data class for session information"""
    fake_to_real_mapping: Dict[str, str]
    original_text: str
    anonymized_text: str
    timestamp: str
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

class AnonymizerProvider(BaseProvider):
    """Custom Faker provider for anonymization"""
    
    def anonymize_person(self, person_name: str) -> str:
        return self.generator.name()
    
    def anonymize_email(self, email: str) -> str:
        return self.generator.email()
    
    def anonymize_phone(self, phone: str) -> str:
        return self.generator.phone_number()
    
    def anonymize_credit_card(self, credit_card: str) -> str:
        return self.generator.credit_card_number()
    
    def anonymize_address(self, address: str) -> str:
        return self.generator.address().replace("\n", ", ")
    
    def anonymize_zip(self, zip_code: str) -> str:
        return self.generator.postcode()
    
    def anonymize_organization(self, organization: str) -> str:
        return self.generator.company()
    
    def anonymize_location(self, location: str) -> str:
        return self.generator.city()

class SessionManager:
    """Manages session storage and lifecycle"""
    
    def __init__(self, sessions_file: str):
        self.sessions_file = sessions_file
        self._sessions_cache: Dict[str, Dict[str, Any]] = {}
        self._load_sessions()
    
    def _load_sessions(self) -> None:
        """Load sessions from file"""
        try:
            if os.path.exists(self.sessions_file):
                with open(self.sessions_file, 'r') as f:
                    self._sessions_cache = json.load(f)
            else:
                self._sessions_cache = {}
        except (json.JSONDecodeError, IOError):
            self._sessions_cache = {}
    
    def _save_sessions(self) -> None:
        """Save sessions to file"""
        try:
            with open(self.sessions_file, 'w') as f:
                json.dump(self._sessions_cache, f, indent=2)
        except IOError:
            # Log error in production
            pass
    
    def create_session(self, session_id: str, session_data: SessionData) -> None:
        """Create a new session"""
        self._sessions_cache[session_id] = session_data.to_dict()
        self._save_sessions()
    
    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session data by ID"""
        return self._sessions_cache.get(session_id)
    
    def delete_session(self, session_id: str) -> None:
        """Delete a session"""
        if session_id in self._sessions_cache:
            del self._sessions_cache[session_id]
            self._save_sessions()

class AnonymizationService:
    """Handles text anonymization logic"""
    
    def __init__(self):
        self.analyzer = AnalyzerEngine()
        self.fake = Faker()
        self.fake.add_provider(AnonymizerProvider)
    
    def _generate_fake_value(self, entity_type: str, original_value: str = "") -> str:
        """Generate fake value for given entity type"""
        mapping = {
            "PERSON": lambda: self.fake.anonymize_person(original_value),
            "EMAIL_ADDRESS": lambda: self.fake.anonymize_email(original_value),
            "PHONE_NUMBER": lambda: self.fake.anonymize_phone(original_value),
            "CREDIT_CARD": lambda: self.fake.anonymize_credit_card(original_value),
            "ADDRESS": lambda: self.fake.anonymize_address(original_value),
            "ZIP": lambda: self.fake.anonymize_zip(original_value),
            "ORGANIZATION": lambda: self.fake.anonymize_organization(original_value),
            "LOCATION": lambda: self.fake.anonymize_location(original_value)
        }
        return mapping.get(entity_type, lambda: f"<{entity_type}>")()
    
    def _create_fake_mapping(self, text: str, results: List) -> Dict[str, str]:
        """Create mapping of fake values to real values"""
        fake_to_real_mapping = {}
        
        for result in results:
            real_value = text[result.start:result.end]
            fake_value_generated = self._generate_fake_value(result.entity_type, real_value)
            
            # Ensure fake value is unique
            while fake_value_generated in fake_to_real_mapping.values():
                fake_value_generated = self._generate_fake_value(result.entity_type, real_value)
            
            fake_to_real_mapping[fake_value_generated] = real_value
        
        return fake_to_real_mapping
    
    def _replace_entities_in_text(self, text: str, results: List, fake_mapping: Dict[str, str]) -> str:
        """Replace detected entities with fake values"""
        anonymized_text = text
        offset = 0
        
        for result in results:
            real_value = text[result.start:result.end]
            fake_value_generated = None
            
            # Find the fake value for this real value
            for fake_val, real_val in fake_mapping.items():
                if real_val == real_value:
                    fake_value_generated = fake_val
                    break
            
            if fake_value_generated:
                # Calculate adjusted positions due to previous replacements
                adjusted_start = result.start + offset
                adjusted_end = result.end + offset
                
                # Replace the text
                anonymized_text = (
                    anonymized_text[:adjusted_start] + 
                    fake_value_generated + 
                    anonymized_text[adjusted_end:]
                )
                
                # Update offset for next replacements
                offset += len(fake_value_generated) - len(real_value)
        
        return anonymized_text
    
    def anonymize_text(self, text: str) -> tuple[str, Dict[str, str]]:
        """Anonymize text and return anonymized text with mapping"""
        # Analyze text for PII
        results = self.analyzer.analyze(text=text, language="en")
        
        # Filter for supported entities
        results = [r for r in results if r.entity_type in SUPPORTED_ENTITIES]
        
        # Sort results by start position to process in order
        results.sort(key=lambda x: x.start)
        
        # Create mapping and anonymize
        fake_mapping = self._create_fake_mapping(text, results)
        anonymized_text = self._replace_entities_in_text(text, results, fake_mapping)
        
        return anonymized_text, fake_mapping
    
    def deanonymize_text(self, text: str, fake_mapping: Dict[str, str]) -> str:
        """Deanonymize text using the mapping"""
        for fake_val, real_val in fake_mapping.items():
            text = text.replace(fake_val, real_val)
        return text

# Initialize services
session_manager = SessionManager(SESSIONS_FILE)
anonymization_service = AnonymizationService()

@app.route("/v1/anonymize", methods=["POST"])
def anonymize_text():
    """Anonymize text endpoint"""
    try:
        data = request.get_json()
        if not data or "text" not in data:
            return jsonify({"error": "Missing 'text' field"}), 400
        
        text = data.get("text", "")
        session_id = str(uuid.uuid4())
        
        # Anonymize the text
        anonymized_text, fake_mapping = anonymization_service.anonymize_text(text)
        
        # Create session data
        session_data = SessionData(
            fake_to_real_mapping=fake_mapping,
            original_text=text,
            anonymized_text=anonymized_text,
            timestamp=datetime.now(timezone.utc).isoformat()
        )
        
        # Save session
        session_manager.create_session(session_id, session_data)
        
        return jsonify({
            "session_id": session_id,
            "original_text": text,
            "anonymized_text": anonymized_text,
            "entities":fake_mapping
        })
    
    except Exception as e:
        return jsonify({"error": f"Anonymization failed: {str(e)}"}), 500

@app.route("/v1/deanonymize", methods=["POST"])
def deanonymize_text():
    """Deanonymize text endpoint"""
    try:
        data = request.get_json()
        if not data or "session_id" not in data:
            return jsonify({"error": "Missing 'session_id' field"}), 400
        
        session_id = data.get("session_id")
        session_data = session_manager.get_session(session_id)
        
        if not session_data:
            return jsonify({"error": "Invalid session_id"}), 400
        
        # Deanonymize the text
        original_text = anonymization_service.deanonymize_text(
            session_data["anonymized_text"], 
            session_data["fake_to_real_mapping"]
        )
        
        # Remove session after deanonymize
        session_manager.delete_session(session_id)
        
        return jsonify({"original_text": original_text})
    
    except Exception as e:
        return jsonify({"error": f"Deanonymization failed: {str(e)}"}), 500

@app.route("/v1/session/<session_id>", methods=["GET"])
def get_session(session_id: str):
    """Get session information endpoint"""
    try:
        session_data = session_manager.get_session(session_id)
        
        if not session_data:
            return jsonify({"error": "Invalid session"}), 400
        
        return jsonify(session_data)
    
    except Exception as e:
        return jsonify({"error": f"Session retrieval failed: {str(e)}"}), 500



# This must be at the module level, not inside a function!
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)  # Changed debug to True for testing