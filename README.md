# SOC Analyst Assistant

### Security Alert Triage, Threat Intelligence & Incident Reporting

A Python-based SOC analyst assistant designed to demonstrate practical security monitoring and investigation workflows.

The project collects Windows security events, identifies suspicious authentication activity, enriches alerts with external threat intelligence, uses an AI model to assist with investigation summaries, and generates incident reports through a Flask web dashboard.

> **Project type:** Cybersecurity / SOC / Blue Team  
> **Status:** Academic & Portfolio Project

---

## Project Objective

SOC analysts often need to investigate large numbers of security alerts and correlate information from different sources.

This project demonstrates how common SOC investigation tasks can be combined into a single workflow:

**Security Logs → Detection → Alert Triage → Threat Intelligence → AI-Assisted Analysis → Incident Report**

The goal is to build practical experience with security monitoring, alert investigation, automation, and incident reporting.

---

## Key Features

| Feature | Description |
|---|---|
| Security Alert Dashboard | Displays collected security alerts with severity and status |
| Windows Event Monitoring | Reads Windows security events for analysis |
| Brute-Force Detection | Identifies repeated failed authentication attempts |
| Threat Intelligence | Investigates IP addresses using VirusTotal and AbuseIPDB |
| AI-Assisted Investigation | Generates investigation summaries and recommended actions |
| Incident Reporting | Generates PDF investigation reports |
| Investigation History | Stores investigation results in SQLite |
| Authentication | Provides login-based access to the dashboard |
| Log Ingestion | Supports receiving logs through an API endpoint |
| Sample Log Generation | Generates test logs for development and demonstration |

---

## Architecture

```text
              Windows Security Events
                       │
                       ▼
             Windows Log Reader
                       │
                       ▼
              Detection Engine
                       │
              ┌────────┴────────┐
              ▼                 ▼
        Alert Dashboard    Brute-Force
                            Detection
              │
              ▼
        IP Investigation
              │
       ┌──────┴──────┐
       ▼             ▼
 VirusTotal      AbuseIPDB
       │             │
       └──────┬──────┘
              ▼
        AI Investigation
              │
              ▼
       Investigation Summary
              │
              ▼
       PDF Incident Report
              │
              ▼
          SOC Dashboard
