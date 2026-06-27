# 🛡️ Wazuh Alert Triage Tool

A Python-based incident triage tool that connects directly to a **live Wazuh deployment** to retrieve, analyze, and report security alerts. The tool automates the first phase of incident response by collecting alerts from the Wazuh Indexer (OpenSearch), identifying suspicious activity, extracting Indicators of Compromise (IOCs), generating an investigation timeline, and producing analyst-friendly Markdown and HTML reports.

---

## 🚀 Features

- 🔴 Live Wazuh Indexer integration
- 📊 Automatic threat analysis and risk scoring
- 🕒 Investigation timeline generation
- 🎯 MITRE ATT&CK technique mapping
- 🔍 Indicator of Compromise (IOC) extraction
- 📄 HTML incident report generation
- 📝 Markdown report generation
- 📈 Severity distribution
- 🖥️ Agent activity summary
- ⚡ Works directly with a live Wazuh/OpenSearch deployment

---

## 📸 Screenshots

### Live Investigation Timeline

> *(Insert screenshot here)*

### Threat Findings

> *(Insert screenshot here)*

### Indicators of Compromise

> *(Insert screenshot here)*

### HTML Report

> *(Insert screenshot here)*

---

## 🏗️ Architecture

```
             +-------------------+
             |   Wazuh Manager   |
             +---------+---------+
                       |
                 REST API / Alerts
                       |
             +---------v---------+
             |   Wazuh Indexer   |
             |   (OpenSearch)    |
             +---------+---------+
                       |
                HTTPS Queries
                       |
             +---------v---------+
             |  Alert Triage Tool|
             +---------+---------+
                       |
       +---------------+----------------+
       |               |                |
 Investigation   IOC Extraction   Threat Detection
 Timeline        MITRE Mapping    Risk Scoring
       |               |                |
       +---------------+----------------+
                       |
              Markdown / HTML Reports
```

---

## 📂 Project Structure

```
wazuh-alert-triage/
│
├── alert_parser.py
├── detector.py
├── display.py
├── ioc.py
├── opensearch_api.py
├── reports.py
├── timeline.py
├── triage.py
│
├── reports/
│   ├── incident-report.md
│   └── incident-report.html
│
└── README.md
```

---

## ⚙️ Technologies Used

- Python 3
- Wazuh 4.x
- OpenSearch
- Requests
- PrettyTable
- HTML/CSS
- Markdown

---

## 🔍 Analysis Performed

The tool automatically:

- Retrieves alerts from the Wazuh Indexer
- Builds an investigation timeline
- Detects suspicious activity
- Maps events to MITRE ATT&CK techniques
- Calculates an overall risk score
- Extracts Indicators of Compromise
- Generates professional investigation reports

---

## 🛡️ Supported Detection Examples

- SSH authentication activity
- Sudo execution
- Privilege escalation attempts
- USB device events
- PowerShell execution
- Encoded PowerShell commands
- High severity Wazuh rules
- Suspicious process execution

---

## 📊 Example Output

```
Risk Score: 72/100

Threats Detected
----------------
✓ SSH Login Activity
✓ Privilege Escalation
✓ USB Device Activity

MITRE ATT&CK
------------
T1021.004 - SSH
T1548 - Abuse Elevation Control Mechanism
T1200 - Hardware Additions

Reports Generated
-----------------
incident-report.md
incident-report.html
```

---

## ▶️ Usage

Run against a live Wazuh deployment:

```bash
python triage.py --live
```

The tool will prompt for:

- Wazuh Indexer URL
- Username
- Password

---

## 📈 Future Improvements

- Detection rule expansion
- Additional MITRE ATT&CK mappings
- VirusTotal integration
- Threat intelligence feeds
- Interactive web dashboard
- Email notifications
- Sigma rule support
- GeoIP enrichment
- YARA scan integration

---

## 🎯 Learning Objectives

This project demonstrates experience with:

- Security Operations (SOC)
- Incident Response
- Threat Detection
- Log Analysis
- SIEM Technologies
- Wazuh
- OpenSearch
- Python Automation
- MITRE ATT&CK
- Security Reporting

---

## 👨‍💻 Author

**Tyler Deppa**

Cybersecurity Student

- 🏆 Top 1% on TryHackMe
- 💎 #1 Diamond Rank
- 🔐 Passionate about Blue Team Operations, Detection Engineering, and Incident Response

GitHub:
https://github.com/cojjjj

LinkedIn:
https://www.linkedin.com/in/tyler-deppa-2523a0345/

---

## 📜 License

This project is licensed under the MIT License.
