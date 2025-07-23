"""
Simple Chat Application for Testing Medical Data Anonymizer
Run with: python chat_app.py
Access at: http://localhost:5000
"""

from flask import Flask, render_template_string, request, jsonify, session
import json
import uuid
import os
from datetime import datetime
from collections import OrderedDict

# Import your anonymizer modules
from anonymizer import (anonymizer, de_anonymizer, anonymize_profile, 
                       de_anonymize_profile, anonymize_json, de_anonymize_json)
from comprehend import detect_pii_data
from db_methods import get_anonymization_statistics

app = Flask(__name__)
app.secret_key = 'your-secret-key-for-testing'

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
    </style>
</head>
<body>
    <h1>Medical Data Anonymizer Test Chat</h1>
    
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
        <button class="example-btn" onclick="loadExample('devices')">Device IDs</button>
        <button class="example-btn" onclick="loadExample('conversation')">Patient Conversation</button>
        <button class="example-btn" onclick="loadExample('profile')">Patient Profile</button>
        <button class="example-btn json-btn" onclick="loadExample('json_example')">JSON Example</button>
        <button class="example-btn json-btn" onclick="loadExample('json_nested')">Nested JSON</button>
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
                    const openBrackets = (fixedInput.match(/\[/g) || []).length;
                    const closeBrackets = (fixedInput.match(/\]/g) || []).length;
                    
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
                
                // Display any entities detected
                if (data.entities_detected === 0) {
                    showWarning('No entities were detected for anonymization. The anonymizer may not have recognized the medical content.');
                } else {
                    showSuccess(`Successfully anonymized ${data.entities_detected} entities.`);
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
                    showSuccess(`Successfully restored ${data.entities_restored} entities.`);
                } else {
                    showWarning('No entities were restored. This may indicate the data was not properly anonymized.');
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
                display.innerHTML = '<div class="entities">No entities detected</div>';
                return;
            }
            
            const entityTypes = {};
            entities.forEach(e => {
                if (!entityTypes[e.Type]) entityTypes[e.Type] = [];
                entityTypes[e.Type].push(e.originalData);
            });
            
            let html = '<div class="entities"><strong>Detected Entities:</strong><br>';
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
                Entities Detected: ${stats.entities_detected}<br>
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
                html += `Medical Entities: ${data.medical_entities}<br>`;
                html += `PII Entities: ${data.pii_entities}<br>`;
                html += `Enhanced Entities: ${data.enhanced_entities}<br>`;
                
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
                
                devices: `Implanted Devices: stefr7678
Pacemaker Serial Number: PM-789456123
Insulin pump ID: INS-456789ABC
Clinical Trial: NCT12345678`,
                
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
                
                json_nested: `{
  "current_symptoms": {
    "sleep_patterns": [
      "good sleep",
      "daytime naps",
      "nightmares",
      "snoring",
      "occasional talking during sleep"
    ],
    "physical_challenges": [],
    "cognitive_challenges": [
      "Mild Cognitive Impairment",
      "Alzheimer's"
    ],
    "neuropsychiatric_symptoms": {
      "other": [],
      "apathy": [],
      "anxiety": [
        "developing symptoms of anxiety during stressful period"
      ],
      "agitation": [],
      "delusions": [],
      "depression": [
        "developing symptoms of depression during stressful period"
      ],
      "irritability": [],
      "hallucinations": []
    },
    "instrumental_activities_daily_living": {
      "laundry": [],
      "shopping": [],
      "housekeeping": [],
      "communication": [],
      "transportation": [
        "trouble finding your way while driving"
      ],
      "food_preparation": [],
      "managing_finances": [
        "difficulties managing finances"
      ],
      "managing_medications": []
    }
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
  "patient_background": {
    "family_history": {
      "father": "diagnosed with Alzheimer's in his early 80s",
      "mother": "diagnosed with vascular dementia and frontotemporal dementia in her 90s"
    },
    "symptom_duration": "more than 10 years",
    "employment_status": "retired",
    "caregiving_history": "carer for your poorly mother",
    "previous_occupation": "led the council's work on research and policy, conducted surveys and statistical analyses, and chaired meetings"
  },
  "bhc_team_discussion": {
    "lumbar_puncture_notes": [
      "discussion about lumbar puncture as a routine procedure",
      "patient expressed interest in participating in the research project but declined the option of lumbar puncture"
    ]
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

# This must be at the module level, not inside a function!
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)  # Changed debug to True for testing
