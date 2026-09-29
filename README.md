# Intelligent AI Firewall

An AI-powered network security system that continuously monitors live network traffic, detects anomalous behavior, identifies potential attacks, calculates risk levels, and dynamically enforces Zero Trust firewall policies.

## 🚀 Overview

The **Intelligent AI Firewall** combines machine learning, network traffic analysis, attack detection, risk scoring, and Windows Firewall enforcement into a single security framework.

The system captures live IP traffic using **Scapy**, analyzes network behavior using an **Isolation Forest** model, detects suspicious activities such as **DDoS/burst attacks and port scans**, and applies dynamic firewall policies based on calculated risk levels.

The main API is implemented using **FastAPI** and provides dashboard and traffic-monitoring endpoints.

## ✨ Key Features

* 🔍 Live network traffic monitoring
* 🤖 AI-based anomaly detection
* 🧠 Machine-learning-based traffic classification
* 🛡️ DDoS/burst attack detection
* 🔎 Port-scan detection
* 📊 Dynamic risk scoring
* 🔐 Zero Trust security policy enforcement
* 🚫 Automatic malicious IP blocking
* 🪟 Windows Defender Firewall integration
* 📝 Firewall activity logging
* 📈 Live security dashboard API
* 🌐 FastAPI REST endpoints
* 💾 Stateful IP and packet-rate tracking

## 🏗️ System Architecture

```text
                    ┌─────────────────────┐
                    │   Live Network      │
                    │      Traffic       │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │   Scapy Packet      │
                    │     Capture         │
                    └──────────┬──────────┘
                               │
                               ▼
              ┌────────────────────────────────┐
              │      Feature Extraction        │
              │                                │
              │ Source IP                      │
              │ Destination IP                 │
              │ Protocol                       │
              │ Port                           │
              │ Packet Size                    │
              │ Packet Rate                    │
              └───────────────┬────────────────┘
                              │
                              ▼
                 ┌─────────────────────────┐
                 │   Isolation Forest      │
                 │  Anomaly Detection      │
                 └────────────┬────────────┘
                              │
                              ▼
                 ┌─────────────────────────┐
                 │     Risk Scoring        │
                 │                         │
                 │ LOW / MEDIUM / HIGH     │
                 └────────────┬────────────┘
                              │
                 ┌────────────┴────────────┐
                 ▼                         ▼
       ┌──────────────────┐       ┌──────────────────┐
       │ Attack Detection │       │ AI Classification│
       │                  │       │                  │
       │ DDoS             │       │ Random Forest    │
       │ Port Scan        │       │ Classifier       │
       └─────────┬────────┘       └─────────┬────────┘
                 └────────────┬────────────┘
                              ▼
                  ┌────────────────────────┐
                  │   Zero Trust Policy    │
                  │                        │
                  │ ALLOW                  │
                  │ RESTRICT               │
                  │ BLOCK                  │
                  └────────────┬───────────┘
                               │
                               ▼
                  ┌────────────────────────┐
                  │   Windows Firewall     │
                  │      Enforcement       │
                  └────────────┬───────────┘
                               │
                               ▼
                    ┌────────────────────┐
                    │ Firewall Logging   │
                    └────────────────────┘
```

## 🧠 Machine Learning

### 1. Isolation Forest

The project uses **Isolation Forest** for unsupervised anomaly detection.

The model uses:

* Protocol
* Destination port
* Packet size
* Packet rate

The implementation creates an Isolation Forest with 100 estimators and a contamination value of 0.05.

The model produces:

* Anomaly prediction
* Anomaly score

These values are then used by the risk-scoring system.

### 2. Random Forest Classifier

A Random Forest classifier is also included for traffic classification.

The classifier uses:

* Protocol
* Port
* Packet size

as input features.

The current implementation trains using normal-traffic dummy labels, so the classifier should be considered a prototype component rather than a fully trained attack-classification model.

## 🔍 Attack Detection

The system currently implements two rule-based attack detection mechanisms.

### DDoS / Burst Detection

The state tracker calculates packets per second for each source IP.

An IP is identified as a burst attack when its traffic rate reaches the configured threshold.

### Port Scan Detection

The system maintains a set of ports accessed by each source IP.

If an IP accesses more than 10 different ports, it is classified as:

```text
PORT_SCAN
```

Otherwise, the traffic is classified as:

```text
NORMAL
```

## 📊 Risk Scoring

The anomaly score generated by Isolation Forest is converted into a numerical risk score between conceptual risk ranges.

```text
Risk Score < 30
       ↓
LOW

30 ≤ Risk Score < 70
       ↓
MEDIUM

Risk Score ≥ 70
       ↓
HIGH
```

The implementation calculates the score using the absolute anomaly score multiplied by 1000.

## 🔐 Zero Trust Enforcement

The firewall follows a simple Zero Trust policy:

| Risk Level | Action   |
| ---------- | -------- |
| LOW        | ALLOW    |
| MEDIUM     | RESTRICT |
| HIGH       | BLOCK    |

High-risk traffic triggers a Windows Firewall block rule for the source IP.

The IP is also stored in the application's in-memory banned-IP tracker so the dashboard can display blocked addresses.

## 🪟 Windows Firewall Integration

The project integrates directly with Windows Firewall using the `netsh advfirewall` command.

For a blocked IP, the system creates a rule similar to:

```text
Intelligent_Firewall_Block_<IP>
```

and applies:

```text
dir=in
action=block
remoteip=<IP>
```

### Administrator Privileges

Because the application modifies Windows Firewall rules, it may require **Administrator privileges**.

If permission is denied, the application reports that administrator privileges are required.

## 📡 Live Traffic Capture

The system uses **Scapy** to capture live IP packets.

For TCP and UDP traffic, it extracts:

```text
Source IP
Destination IP
Protocol
Destination Port
Packet Size
Timestamp
```

Traffic capture is performed using Scapy's packet sniffing functionality.

## 📁 Project Structure

```text
Intelligent-AI-Firewall/
│
├── api.py
├── main.py
│
├── live_traffic.py
├── isolation_forest.py
├── attack_detection.py
├── attack_classifier.py
├── risk_scoring.py
│
├── zero_trust_policy.py
├── windows_firewall.py
├── firewall_logger.py
├── state_tracker.py
│
└── README.md
```

### File Description

| File                   | Purpose                                     |
| ---------------------- | ------------------------------------------- |
| `api.py`               | FastAPI application and dashboard endpoints |
| `main.py`              | Basic firewall execution workflow           |
| `live_traffic.py`      | Captures live network packets               |
| `isolation_forest.py`  | Anomaly detection using Isolation Forest    |
| `attack_detection.py`  | Detects DDoS/burst and port-scan behavior   |
| `attack_classifier.py` | Random Forest traffic classification        |
| `risk_scoring.py`      | Converts anomaly scores into risk levels    |
| `zero_trust_policy.py` | Applies ALLOW/RESTRICT/BLOCK policies       |
| `windows_firewall.py`  | Controls Windows Firewall rules             |
| `firewall_logger.py`   | Creates firewall activity logs              |
| `state_tracker.py`     | Tracks IP packet rates and banned IPs       |

## ⚙️ Requirements

Recommended environment:

* Windows 10/11
* Python 3.9+
* Administrator privileges
* Npcap/WinPcap-compatible packet capture environment

Python libraries:

```bash
pip install fastapi uvicorn pandas scikit-learn scapy
```

## 🔧 Installation

### 1. Clone the Repository

```bash
git clone <your-repository-url>
cd Intelligent-AI-Firewall
```

### 2. Create a Virtual Environment

```bash
python -m venv venv
```

### 3. Activate the Environment

Windows CMD:

```bash
venv\Scripts\activate
```

PowerShell:

```powershell
venv\Scripts\Activate.ps1
```

### 4. Install Dependencies

```bash
pip install fastapi uvicorn pandas scikit-learn scapy
```

## ▶️ Running the Project

### Run the FastAPI Application

```bash
uvicorn api:app --reload
```

The API will normally be available at:

```text
http://127.0.0.1:8000
```

FastAPI automatically provides interactive API documentation at:

```text
http://127.0.0.1:8000/docs
```

## 🌐 API Endpoints

### Live Dashboard

```http
GET /live-dashboard
```

Returns:

* Total traffic
* Blocked traffic count
* Firewall logs
* Banned IP addresses
* Attack summary

The dashboard endpoint performs anomaly detection, risk scoring, attack detection, AI classification, Zero Trust enforcement, and logging.

### Traffic

```http
GET /traffic
```

Captures and returns live traffic information.

### Run Firewall

```http
GET /run-firewall
```

Runs the basic traffic-analysis workflow and returns the number of processed traffic records.

## 🔄 Processing Workflow

```text
1. Capture live packets
        ↓
2. Extract network features
        ↓
3. Calculate packet rate
        ↓
4. Isolation Forest anomaly detection
        ↓
5. Calculate anomaly/risk score
        ↓
6. Detect known attack patterns
        ↓
7. Classify traffic
        ↓
8. Apply Zero Trust policy
        ↓
9. Block high-risk IPs
        ↓
10. Generate firewall logs
        ↓
11. Return dashboard results
```

At application startup, the API captures baseline traffic and uses it to train the anomaly-detection model and attack-classification component.

## 📝 Firewall Logging

Each firewall decision can contain:

```json
{
  "timestamp": "2026-09-29 13:00:00",
  "src_ip": "192.168.1.10",
  "dst_ip": "192.168.1.20",
  "protocol": "TCP",
  "port": 443,
  "packet_size": 512,
  "risk_level": "HIGH",
  "action": "BLOCK"
}
```

The logging module records timestamp, source/destination IPs, protocol, port, packet size, risk level, and firewall action.

## 🛡️ Security Model

The project follows a layered security approach:

```text
Network Monitoring
        ↓
Anomaly Detection
        ↓
Attack Detection
        ↓
Risk Assessment
        ↓
Zero Trust Decision
        ↓
Firewall Enforcement
        ↓
Security Logging
```

This provides multiple stages of analysis instead of relying solely on a single detection mechanism.

## ⚠️ Current Limitations

This version is a prototype/research implementation.

Important limitations include:

* The Random Forest classifier currently uses dummy normal-traffic labels rather than a labeled attack dataset.
* Firewall state is stored in memory.
* Banned IP information is not persisted in a database.
* The system currently targets Windows Firewall.
* Administrator privileges may be required for blocking IP addresses.
* The anomaly model is trained from captured baseline traffic at application startup.
* Attack detection currently focuses on burst/DDoS-style traffic and port scanning.
* The current risk formula is a simple transformation of the Isolation Forest anomaly score.

## 🔮 Future Enhancements

Possible future improvements include:

* PostgreSQL/MySQL security-event database
* Redis-based state management
* Celery/RQ background processing
* Real labeled cybersecurity datasets
* Improved supervised attack classification
* Deep-learning-based anomaly detection
* Authentication and authorization for the API
* JWT-based dashboard security
* HTTPS/TLS deployment
* Docker containerization
* SIEM integration
* Email/SMS security alerts
* GeoIP analysis
* Threat-intelligence API integration
* Persistent firewall-rule management
* Advanced attack types such as:

  * Brute Force
  * SQL Injection
  * Web attacks
  * Malware traffic
  * Botnet traffic
  * DNS attacks
* React-based real-time security dashboard
* Historical analytics and reporting

## 🎯 Project Objective

The objective of the Intelligent AI Firewall is to demonstrate how **machine learning + network monitoring + Zero Trust security + automated firewall enforcement** can be combined to create an adaptive network-defense system.

The system is designed to move beyond traditional static firewall rules by analyzing traffic behavior and dynamically responding to potentially malicious activity.

## 👨‍💻 Technologies Used

```text
Python
FastAPI
Scapy
Pandas
Scikit-learn
Isolation Forest
Random Forest
Windows Firewall
Netsh
Zero Trust Architecture
REST API
Machine Learning
Network Security
```

## 📜 License

This project is intended for educational, research, and cybersecurity experimentation purposes.

Use the firewall-enforcement functionality responsibly and only on systems and networks that you own or are authorized to administer.

## 👤 Author

**Srikar Godishela**

Cybersecurity / Computer Science Engineering Student

---

⭐ If you find this project useful, consider giving the repository a star.
