import os
from groq import Groq
from dotenv import load_dotenv

load_dotenv('.env')

client = Groq(api_key=os.getenv('GROQ_API_KEY'))

def generate_ai_summary(alert_data, investigation_data):
    abuse = investigation_data.get('abuseipdb', {})
    vt = investigation_data.get('virustotal', {})
    threat_level = investigation_data.get('threat_level', 'Unknown')

    prompt = f"""
You are an expert SOC analyst. Analyze this security alert and provide a clear investigation summary.

ALERT DETAILS:
- Alert Type: {alert_data.get('type', 'Unknown')}
- Event ID: {alert_data.get('event_id', 'Unknown')}
- Source IP: {investigation_data.get('ip', 'Unknown')}
- Username Targeted: {alert_data.get('username', 'Unknown')}
- Timestamp: {alert_data.get('timestamp', 'Unknown')}
- Severity: {alert_data.get('severity', 'Unknown')}

THREAT INTELLIGENCE:
- Threat Level: {threat_level}
- AbuseIPDB Score: {abuse.get('abuse_score', 0)}%
- Country: {abuse.get('country', 'Unknown')}
- ISP: {abuse.get('isp', 'Unknown')}
- Total Abuse Reports: {abuse.get('total_reports', 0)}
- TOR Node: {abuse.get('is_tor', False)}
- VirusTotal Malicious Detections: {vt.get('malicious', 0)}
- VirusTotal Suspicious: {vt.get('suspicious', 0)}

Provide your response in exactly this format:

SUMMARY:
[2-3 sentences explaining what happened and how serious it is]

ATTACK TYPE:
[Identify the specific attack type]

RECOMMENDED ACTIONS:
1. [First action]
2. [Second action]
3. [Third action]

ESCALATE TO L2:
[Yes or No and why]
"""

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=400,
        temperature=0.3
    )

    return response.choices[0].message.content