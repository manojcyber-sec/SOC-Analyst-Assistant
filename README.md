# 🛡️ SOC Analyst Assistant
### AI-Powered Alert Triage & Incident Response Platform

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-2.0+-green?style=flat-square&logo=flask)
![AI Powered](https://img.shields.io/badge/AI-Groq%20LLaMA-purple?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)

A real-world SOC (Security Operations Center) tool that automates alert triage, threat investigation, and incident reporting — making a SOC L1 analyst's job **180x faster** than manual processes.

---

## 🎯 Problem It Solves

A SOC L1 analyst receives **500-1000 alerts per day**. For each alert they manually:
- Check IP reputation on VirusTotal (3 minutes)
- Check abuse history on AbuseIPDB (2 minutes)
- Write investigation notes (10 minutes)
- Generate incident report (45 minutes)

**Total: ~60 minutes per alert. For 500 alerts — impossible.**

This tool reduces that to **20 seconds per alert** using AI and automation.

---

## ⚡ Features

| Feature | Description |
|---|---|
| 🔴 Live Alert Feed | Real-time Windows security event monitoring |
| 🔍 One-Click IP Investigation | Auto-queries VirusTotal + AbuseIPDB instantly |
| 🤖 AI Investigation Summary | LLaMA AI analyzes threats and recommends actions |
| 🚨 Brute Force Detection | Groups repeated failures into single Critical alert |
| 📄 PDF Incident Report | Professional report generated in one click |
| 💾 Investigation History | All investigations saved to SQLite database |
| 🔐 Secure Login | Session-based authentication system |
| 🔄 Auto Refresh | Dashboard updates every 30 seconds |
| 📡 Multi-Machine Support | Any machine on network can send logs via API |
| ✅ Alert Status Management | Mark alerts Open / Investigating / Closed |

---

## 🖥️ Screenshots

### Dashboard
> Live alert feed with severity classification and status management

### IP Investigation Modal
> Real-time threat intelligence from VirusTotal and AbuseIPDB with AI analysis

### PDF Incident Report
> Professional one-click incident report generation

---

## 🏗️ Architecture

```
Windows Security Logs (Event IDs: 4624, 4625, 4740, 4720, 4648, 4688)
          │
          ▼
  Log Parser & Brute Force Detection Engine
          │
          ▼
     SQLite Database ◄──── Alert Status Updates
          │
          ▼
    Flask Web Server
          │
    ┌─────┴─────┐
    ▼           ▼
VirusTotal   AbuseIPDB
    API          API
    └─────┬─────┘
          ▼
      Groq AI (LLaMA)
      Investigation Summary
          │
          ▼
    PDF Report Generator
          │
          ▼
    SOC Dashboard (Browser)
```

---

## 🛠️ Tech Stack

- **Backend:** Python, Flask
- **Database:** SQLite
- **AI:** Groq API (LLaMA 3.3 70B)
- **Threat Intel:** VirusTotal API, AbuseIPDB API
- **Frontend:** HTML, CSS, JavaScript
- **PDF:** ReportLab
- **Log Collection:** PowerShell + Windows Event API

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Windows OS (for real log collection)
- Free API keys: VirusTotal, AbuseIPDB, Groq

### Installation

```bash
# Clone the repository
git clone https://github.com/manojcyber-sec/SOC-Analyst-Assistant.git
cd SOC-Analyst-Assistant

# Install dependencies
pip install flask requests reportlab groq python-dotenv

# Create environment file
cp .env.example .env
# Add your API keys to .env file

# Generate sample logs (optional)
python log_generator.py

# Run as Administrator (required for Windows log access)
python app.py
```

### Environment Setup

Create a `.env` file with:
```
ABUSEIPDB_KEY=your_abuseipdb_key_here
VIRUSTOTAL_KEY=your_virustotal_key_here
GROQ_API_KEY=your_groq_key_here
```

### Access

Open browser and go to: `http://127.0.0.1:5000`

**Default Credentials:**
| Username | Password |
|---|---|
| admin | soc@2026 |
| analyst | analyst@2026 |

---

## 📡 Multi-Machine Log Ingestion

Any machine on your network can send logs to this tool:

```python
import requests

logs = [
    {
        "event_id": "4625",
        "type": "Failed Login",
        "severity": "Medium",
        "source_ip": "192.168.1.50",
        "username": "admin",
        "timestamp": "2026-05-19 10:30:00"
    }
]

requests.post("http://YOUR_SERVER_IP:5000/ingest", json={"logs": logs})
```

---

## 🔍 Supported Windows Event IDs

| Event ID | Description | Severity |
|---|---|---|
| 4624 | Successful Login | Low |
| 4625 | Failed Login | Medium |
| 4740 | Account Lockout | High |
| 4720 | New User Created | High |
| 4648 | Login With Explicit Credentials | High |
| 4688 | Process Started | Low |

---

## 🤖 AI Investigation Output

For every investigated IP, the AI provides:

```
SUMMARY:
High-severity alert from IP 45.33.32.156 (Russia). AbuseIPDB score 94%
with 2,847 abuse reports. VirusTotal shows 12 malicious detections.

ATTACK TYPE:
Credential Stuffing / Brute Force Attack

RECOMMENDED ACTIONS:
1. Immediately block IP at firewall level
2. Reset passwords for targeted accounts
3. Enable MFA on affected systems

ESCALATE TO L2:
Yes — critical threat with confirmed malicious history
```

---

## 📊 Comparison with Enterprise Tools

| Feature | This Tool | Splunk | Microsoft Sentinel | Wazuh |
|---|---|---|---|---|
| Cost | **Free** | $150K/year | $200/month | Free |
| Setup Time | **5 minutes** | 2 hours | 1 day | 3 hours |
| AI Investigation | **✅ Built-in** | ❌ | ✅ Paid add-on | ❌ |
| Auto PDF Report | **✅** | ❌ | ❌ | ❌ |
| IP Threat Intel | **✅ Built-in** | Plugin needed | Plugin needed | Plugin needed |
| Brute Force Detection | ✅ | ✅ | ✅ | ✅ |

---

## 📁 Project Structure

```
SOC-Analyst-Assistant/
├── app.py                  # Main Flask application
├── investigator.py         # VirusTotal + AbuseIPDB integration
├── ai_analyst.py           # Groq AI investigation engine
├── report_generator.py     # PDF report generation
├── log_generator.py        # Realistic log simulator
├── windows_log_reader.py   # Real Windows log collection
├── templates/
│   ├── dashboard.html      # Main SOC dashboard
│   └── login.html          # Authentication page
├── data/                   # Alerts and database (gitignored)
├── reports/                # Generated PDF reports (gitignored)
├── .env.example            # Environment variables template
└── .gitignore
```

---

## 🔒 Security Notes

- Never commit your `.env` file
- Change default credentials before deployment
- Run with Administrator privileges for real Windows log access
- API keys are stored locally only

---

## 🗺️ Roadmap

- [ ] Email alerts for Critical threats
- [ ] Geographic attack map visualization
- [ ] Real-time WebSocket log streaming
- [ ] Network agent for automatic multi-machine deployment
- [ ] Docker containerization
- [ ] Multi-tenant support for MSSP use cases

---

## 👤 Author

**Badige Manoj Kumar**
- B.Tech CSE (Cybersecurity) — Alliance University, Bangalore
- GitHub: [@manojcyber-sec](https://github.com/manojcyber-sec)
- LinkedIn: [Connect with me](https://www.linkedin.com/in/manojkumarbadige/)

---

## 📄 License

This project is licensed under the MIT License.

---

> ⭐ If this project helped you, please give it a star on GitHub!
