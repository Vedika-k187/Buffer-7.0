# Buffer-7.0

Our Theme : Cybersecurity and Digital Defense

---

# 🛡️ DNS Guard — Advanced DNS Threat Detection System

## 📌 Problem Statement

DNS-based attacks such as phishing, DNS tunneling, data exfiltration, and typosquatting are increasingly common and difficult to detect using traditional security systems. These attacks often bypass firewalls and operate silently, making them a major cybersecurity threat.

DNSGuard is a real-time DNS traffic monitoring and threat detection system designed to identify suspicious and potentially malicious domains using a combination of rule-based techniques, efficient data structures, and machine learning.

---

## 🚀 Overview

Every time a user accesses a website, a DNS request is generated to resolve the domain name into an IP address. DNS Guard monitors these DNS requests and analyzes domain patterns to detect threats at an early stage.

The system processes DNS data, applies various detection algorithms, and presents results through an interactive dashboard.

---

## 🧠 Key Features

* 🔍 **Entropy Analysis** — Detects random or encoded domains
* 🤖 **Machine Learning (Isolation Forest)** — Identifies anomalies
* 🧬 **Steganography Detection** — Detects hidden encoded data in domains
* 🔤 **Typosquatting Detection** — Identifies lookalike malicious domains
* 🌐 **Trie-based Domain Matching** — Efficient domain lookup
* 📊 **Interactive Dashboard with Live Updates**
* 🌍 **Geolocation-based visualization of DNS traffic**
* ⚡ **Real-time Processing Pipeline**
* 🕒 **Attack Timeline Reconstruction**

---

## 🏗️ System Architecture

1. **Data Input**

   * PCAP files / DNS logs / Live traffic

2. **Processing Layer**

   * Packet capture (Npcap + Scapy)
   * Queue-based processing
   * Feature extraction

3. **Detection Modules**

   * Entropy Detection
   * Sliding Window Detection
   * Typosquatting Detection
   * Steganography Detection
   * ML Anomaly Detection

4. **Storage**

   * PostgreSQL Database

5. **Visualization**

   * Flask-based Dashboard with Socket.IO

---

## 🧩 Data Structures Used

* **Trie**

  * Used for fast domain lookup in typosquatting detection

* **Hash Maps (Dictionaries)**

  * Used for frequency counting in entropy calculation
  * Used in scoring systems

* **Queues (FIFO)**

  * Used for buffering DNS packets between capture and processing

* **Lists**

  * Used to store DNS records and feature vectors

* **Hash Set**

  * Used for deduplication of domains

* **Sliding Window Technique**

  * Used to avoid redundant processing of repeated domains

---

## 🛠️ Tech Stack

* **Backend:** Python, Flask
* **Packet Capture:** Scapy, Npcap
* **Database:** PostgreSQL
* **Machine Learning:** Scikit-learn (Isolation Forest)
* **Frontend:** HTML, CSS, JavaScript
* **Real-time Communication:** Flask-SocketIO
* **Testing:** Pytest

---

## ⚙️ Modes of Operation

### 🔹 Live Monitoring

```bash
python main.py live
```

### 🔹 Full Pipeline Analysis

```bash
python main.py pipeline
```

### 🔹 Simulation Mode

```bash
python main.py simulate
```

### 🔹 PCAP Analysis

```bash
python main.py pcap data/pcap_samples/sample.pcap
```

### 🔹 Dashboard

```bash
python main.py dashboard
```

Access dashboard at:

```
http://127.0.0.1:5000
```

---

## 🎥 Project Demo Video

👉 [Watch Demo Video](https://drive.google.com/file/d/1NuPahuq2ORHsQBqybnrJE7ISVPkEKNTy/view?usp=sharing)

---

## 👩‍💻 Team Members

* Vedika Kurhade
* Dnyaneshwari Khatke
* Mahi Mahalle
* Shreya Jadhav

---

## 📌 Conclusion

DNS Guard provides a multi-layered approach to DNS threat detection by combining statistical analysis, efficient data structures, and machine learning. It enables early detection of DNS-based cyber threats and provides real-time insights through an interactive dashboard.

---

## ⭐ Future Scope

* Real-time DNS blocking and firewall integration
* Integration with threat intelligence APIs (VirusTotal, etc.)
* Improved ML models with larger datasets
* Deployment as a cloud-based security solution
* Support for DNS over HTTPS (DoH)

---
