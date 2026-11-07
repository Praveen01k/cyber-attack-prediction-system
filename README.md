# 🛡️ Cyber Attack Prediction System (Intrusion Detection & Early Warning Engine)

[![Python 3.11](https://img.shields.io/badge/Python-3.11-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.40+-FF4B4B.svg?logo=streamlit&logoColor=white)](https://streamlit.io/)
[![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-Machine%20Learning-F7931E.svg?logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)
[![Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg)]()
[![Course](https://img.shields.io/badge/Course-8CD7--50%20(B.Tech)-9cf.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **B.Tech Capstone Project in Computer Science & Engineering (Specialization: Data Science)**  
> **Institution:** BK Birla Institute of Engineering & Technology (BKBIET), Pilani  
> **Affiliation:** Bikaner Technical University (BTU)  
> **Course Code:** 8CD7-50 | **Group No:** 5  
> **Project Guide:** Suman Kanta  
> **Authors:** [Ajay Saini](mailto:ajayysaiini@gmail.com) (`22EBKDS003`) & [Praveen Sharma](mailto:Praveensharma01k@gmail.com) (`22EBKDS043`)

---

## 📌 Abstract

Cyber attacks are increasing rapidly with the exponential growth of internet technologies, creating severe threats to enterprise infrastructure and critical data. Traditional security systems react passively after damage has already occurred. 

This project implements an intelligent **Cyber Attack Prediction & Early Warning System** utilizing machine learning classifiers to analyze network telemetry and host connection behaviors in real-time. By modeling patterns such as failed login frequencies, anomalous SYN error distributions, and abnormal packet payload ratios, the system accurately identifies and classifies malicious activity into 4 primary attack classes (**DoS**, **Probe**, **R2L**, and **U2R**) against baseline **Normal** traffic. Empirical benchmarking is conducted between **Random Forest** and **Support Vector Machine (SVM)** to evaluate detection accuracy, recall, and false-positive minimization.

---

## 🏗️ System Architecture

```
                                  +---------------------------------------+
                                  |   Raw Network Telemetry / CSV Logs    |
                                  +---------------------------------------+
                                                      |
                                                      v
                                  +---------------------------------------+
                                  |      Feature Engineering Pipeline     |
                                  |  - Categorical Mapping (Proto/Serv)   |
                                  |  - StandardScaler Normalization       |
                                  +---------------------------------------+
                                                      |
                                                      v
                               +---------------------------------------------+
                               |         Trained ML Detection Models         |
                               |  - Random Forest Classifier (Ensemble)      |
                               |  - Support Vector Machine (RBF Kernel)      |
                               +---------------------------------------------+
                                                      |
                         +----------------------------+----------------------------+
                         |                                                         |
                         v                                                         v
         +--------------------------------+                       +----------------------------------+
         |     Multi-Class Attack Label   |                       |    Early Warning & Risk Engine   |
         |  - Normal   - DoS (SYN Flood)  |                       |  - Severity: Low / Med / High    |
         |  - Probe    - R2L (Brute Force)|                       |  - Calibrated Risk Score (0-100) |
         |  - U2R      (Privilege Esc)    |                       |  - iptables Firewall Rules       |
         +--------------------------------+                       +----------------------------------+
                         |                                                         |
                         +----------------------------+----------------------------+
                                                      |
                                                      v
                                  +---------------------------------------+
                                  |    Interactive SOC Web Application    |
                                  |        (Streamlit & Plotly UI)        |
                                  +---------------------------------------+
```

---

## 🚀 Key Features

* **Real-Time Network Packet Inspector:** Analyze individual network packets with interactive sliders or test instant attack presets (*SYN Flood DoS, Nmap Port Scanning, SSH Credential Brute-Force, Buffer Overflow Privilege Escalation*).
* **Automated Early Warning & Defense Playbook:** Generates real-time threat alert banners and dynamic Linux `iptables` containment scripts for immediate incident mitigation.
* **Batch Network Log Scanner:** Upload large network captures (`.csv`) to parse thousands of connections simultaneously with instant KPI metrics, donut charts, and an exportable security audit report.
* **Empirical Model Comparison:** Side-by-side comparison of **Random Forest** vs. **Support Vector Machine (SVM)** with Accuracy, Precision, Recall, F1-Score, Confusion Matrices, and Gini Feature Importances.
* **Comprehensive Attack Coverage:**
  * **DoS (Denial of Service):** SYN Flood, Neptune, Smurf.
  * **Probe (Reconnaissance):** Port scanning, Nmap sweeps, network topology mapping.
  * **R2L (Remote to Local):** Credential stuffing, SSH/FTP brute-forcing, password guessing.
  * **U2R (User to Root):** Buffer overflows, unauthorized root shell invocation.

---

## 📁 Repository Structure

```
cyber-attack-prediction-system/
├── app.py                      # Main Streamlit SOC Web Application
├── requirements.txt            # Python dependencies
├── .gitignore                  # Git ignore rules
├── README.md                   # Project documentation & citations
├── data/
│   ├── generate_dataset.py     # NSL-KDD / CICIDS calibrated data generator
│   ├── cyber_attacks_dataset.csv # 7,500 sample training dataset
│   └── sample_network_traffic.csv# Sample test capture for batch analysis
├── models/
│   ├── random_forest_model.pkl # Trained Random Forest weights
│   ├── svm_model.pkl           # Trained Support Vector Machine weights
│   ├── scaler.pkl              # Fitted StandardScaler instance
│   └── metrics.json            # Benchmarking metrics & confusion matrices
└── src/
    ├── __init__.py
    ├── preprocessing.py        # Feature encoding and data preparation
    ├── mitigations.py          # Incident response rules & firewall generator
    ├── predictor.py            # High-level inference engine
    └── train.py                # Model training and evaluation script
```

---

## ⚙️ Installation & Quickstart

### Prerequisites
* Python 3.10 or higher
* Git

### 1. Clone the Repository
```bash
git clone https://github.com/your-username/cyber-attack-prediction-system.git
cd cyber-attack-prediction-system
```

### 2. Create a Virtual Environment (Optional but Recommended)
```bash
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. (Optional) Re-train the Models
```bash
python src/train.py
```

### 5. Launch the SOC Dashboard
```bash
streamlit run app.py
```
Open your browser at `http://localhost:8501` to access the Security Operations Center dashboard.

---

## 📊 Benchmark Results

| Model | Accuracy | Precision | Recall | F1-Score |
| :--- | :---: | :---: | :---: | :---: |
| **Random Forest Classifier** | **99.9%** | **99.9%** | **99.9%** | **99.9%** |
| **Support Vector Machine (SVM)** | **99.8%** | **99.8%** | **99.8%** | **99.8%** |

---

## 📚 Academic References

1. **Sommer, R., & Paxson, V.** (2010). *Outside the Closed World: On Using Machine Learning for Network Intrusion Detection*. IEEE Symposium on Security and Privacy (SP).
2. **Tavallaee, M., Bagheri, E., Lu, W., & Ghorbani, A. A.** (2009). *A Detailed Analysis of the KDD CUP 99 Data Set*. IEEE Symposium on Computational Intelligence for Security and Defense Applications (CISDA).
3. **Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A.** (2018). *Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization*. International Conference on Information Systems Security and Privacy (ICISSP).
4. **Goodfellow, I., Bengio, Y., & Courville, A.** (2016). *Deep Learning*. MIT Press.

---

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
