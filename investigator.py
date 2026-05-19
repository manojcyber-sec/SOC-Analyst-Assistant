import requests
import os
from dotenv import load_dotenv

load_dotenv('.env')

ABUSEIPDB_KEY = os.getenv('ABUSEIPDB_KEY')
VIRUSTOTAL_KEY = os.getenv('VIRUSTOTAL_KEY')

def check_abuseipdb(ip):
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        response = requests.get(url, headers=headers, params=params, timeout=10)
        data = response.json().get("data", {})
        return {
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "country": data.get("countryCode", "Unknown"),
            "isp": data.get("isp", "Unknown"),
            "total_reports": data.get("totalReports", 0),
            "last_reported": data.get("lastReportedAt", "Never"),
            "is_tor": data.get("isTor", False),
        }
    except Exception as e:
        return {"error": str(e)}

def check_virustotal(ip):
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": VIRUSTOTAL_KEY}
        response = requests.get(url, headers=headers, timeout=10)
        data = response.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "reputation": data.get("reputation", 0),
            "country": data.get("country", "Unknown"),
            "owner": data.get("as_owner", "Unknown"),
        }
    except Exception as e:
        return {"error": str(e)}

def investigate_ip(ip):
    abuse = check_abuseipdb(ip)
    vt = check_virustotal(ip)

    abuse_score = abuse.get("abuse_score", 0)
    vt_malicious = vt.get("malicious", 0)

    if abuse_score > 80 or vt_malicious > 5:
        threat_level = "Critical"
    elif abuse_score > 50 or vt_malicious > 2:
        threat_level = "High"
    elif abuse_score > 20 or vt_malicious > 0:
        threat_level = "Medium"
    else:
        threat_level = "Low"

    return {
        "ip": ip,
        "threat_level": threat_level,
        "abuseipdb": abuse,
        "virustotal": vt
    }