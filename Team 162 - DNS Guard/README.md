

# DNSGuard — Intelligent DNS Threat Monitoring System

DNSGuard is a real-time DNS traffic monitoring and threat detection system designed to identify suspicious and potentially malicious domains using a combination of rule-based techniques, data structures, and machine learning.



# Overview

Every time a user accesses a website, a DNS request is generated to resolve the domain name into an IP address. DNSGuard monitors these DNS requests and analyzes domain patterns to detect threats at an early stage.

The system is capable of identifying:

* Phishing domains
* DNS tunneling activity
* Randomly generated domains (DGA)
* Typosquatting attacks



# Key Features

* Real-time DNS monitoring using Npcap and Scapy
* Machine learning-based anomaly detection using Isolation Forest
* Threat scoring using entropy, heuristics, and ML output
* Interactive dashboard with live updates
* Geolocation-based visualization of traffic
* Attack timeline reconstruction
* Support for simulation and PCAP-based analysis

---

# How It Works

```text
DNS Request
   ↓
Packet Capture (Npcap + Scapy)
   ↓
Data Extraction (domain, IP, query type)
   ↓
Queue Processing
   ↓
Database Storage (PostgreSQL)
   ↓
Analysis Pipeline
   → Entropy Detection
   → DNS Tunneling Detection
   → Typosquatting Detection
   → ML Anomaly Detection (Isolation Forest)
   ↓
Threat Scoring and Alert Generation
   ↓
Dashboard Visualization
```


# Technology Stack

| Layer            | Technology                      |
| ---------------- | ------------------------------- |
| Backend          | Python                          |
| Packet Capture   | Scapy, Npcap                    |
| Machine Learning | Scikit-learn (Isolation Forest) |
| Database         | PostgreSQL                      |
| Backend Server   | Flask, Socket.IO                |
| Frontend         | HTML, CSS, JavaScript           |



# Modes of Operation

### Live Monitoring

Captures DNS traffic in real time.

```bash
python main.py live
```



### Full Analysis Pipeline

Processes stored DNS data.

```bash
python main.py pipeline
```


### Simulation Mode

Generates synthetic attack data.

```bash
python main.py simulate
```



### PCAP Analysis

Analyzes DNS traffic from PCAP files.

```bash
python main.py pcap data/pcap_samples/sample.pcap
```



### Dashboard

Starts the web interface.

```bash
python main.py dashboard
```

Access at:

```
http://127.0.0.1:5000
```



# Detection Techniques

DNSGuard uses a hybrid approach combining rule-based analysis and machine learning.

### Rule-Based Analysis

* Entropy calculation for randomness detection
* Digit ratio and domain length analysis

### Pattern-Based Detection

* Typosquatting detection
* DNS tunneling detection

### Machine Learning

* Isolation Forest for anomaly detection based on domain features



# Data Structures and Algorithms

The system is designed using efficient data structures and algorithms to ensure real-time performance and scalability.

### Queue (FIFO)

* Used for buffering DNS records between capture and processing
* Ensures ordered and asynchronous handling of streaming data

### Hash Map (Dictionary)

* Used for constant-time lookups such as DNS query type mapping
* Used in scoring systems and structured data handling

### Hash Set

* Used for deduplication of domains in real time
* Provides O(1) lookup for detecting repeated queries

### Arrays / Lists

* Used for storing feature vectors for machine learning input

### Graph (Conceptual Implementation)

* Used to model relationships between domains and IPs
* Helps identify shared infrastructure and attack clusters

### Sorting Algorithms

* Used to reconstruct attack timelines based on timestamps

### Sliding Window Technique

* Used to prevent redundant processing of frequently repeated domains



# System Architecture

The system follows a modular and decoupled architecture:

* Packet capture is independent from processing
* Queue-based buffering ensures efficient real-time handling
* Analysis pipeline runs separately for scalability
* Visualization is handled through a web-based dashboard


# Project Structure

```text
DNS_Guard/
│
├── capture/              # Packet capture and queue handling
├── intelligence/         # Detection logic, ML, scoring
├── dashboard/            # Flask backend and frontend UI
├── config/               # Database and logging configuration
├── tests/                # Test scripts
├── main.py               # Entry point
└── requirements.txt
```



# Comparison with Antivirus Systems

| Feature                           | Antivirus | DNSGuard |
| --------------------------------- | --------- | -------- |
| Detects threats before connection | No        | Yes      |
| Monitors DNS traffic              | No        | Yes      |
| Real-time network visibility      | Limited   | Yes      |
| Detects DNS-based attacks         | No        | Yes      |



# Limitations

* Machine learning model is trained on a limited dataset
* The system currently detects threats but does not block them
* Real-time scoring can be further improved



# Future Work

* Real-time threat scoring integration
* DNS-level blocking and firewall capabilities
* Improved ML models with larger datasets
* Integration with threat intelligence feeds
* Support for DNS over HTTPS (DoH)



# Conclusion

DNSGuard provides a proactive approach to cybersecurity by monitoring DNS traffic and detecting suspicious activity at an early stage. The use of efficient data structures and modular design ensures scalability, performance, and adaptability for real-world applications.
=======
venv\Scripts\activate
pip install -r requirements.txt
>>>>>>> f07cde4 (Updated frontend and Add real-time DNS capture, socket streaming, and pipeline separation)
