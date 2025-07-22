"""
Simple Chat Application for Testing Medical Data Anonymizer
Run with: python chat_app.py
Access at: http://localhost:5000
"""

from flask import Flask, render_template_string, request, jsonify, session
import json
import uuid
from datetime import datetime

# Import your anonymizer modules
from anonymizer import anonymizer, de_anonymizer, anonymize_profile, de_anonymize_profile
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
    </style>
</head>
<body>
    <h1>Medical Data Anonymizer Test Chat</h1>
    
    <div class="container">
        <div class="chat-box">
            <h3>Original Text</h3>
            <div id="original-messages" class="chat-messages"></div>
            
            <h3>Input Medical Data</h3>
            <textarea id="chat-input" placeholder="Enter patient data, clinical notes, or conversations..."></textarea>
            
            <div>
                <button onclick="anonymizeText()">Anonymize</button>
                <button onclick="detectEntities()">Detect Entities Only</button>
                <button onclick="clearChat()">Clear</button>
            </div>
            
            <div class="stats" id="stats"></div>
        </div>
        
        <div class="chat-box">
            <h3>Anonymized Text</h3>
            <div id="anonymized-messages" class="chat-messages"></div>
            
            <h3>Actions</h3>
            <button onclick="deAnonymizeLastMessage()">De-Anonymize Last Message</button>
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
    </div>
    
    <script>
        let lastAnonymizedText = '';
        
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
                html += '<strong>By Type:</strong><br>';
                for (const [type, count] of Object.entries(data.entity_types)) {
                    html += `${type}: ${count}<br>`;
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
Medications: Metoprolol 50mg daily, Metformin 500mg BID`
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

    if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
