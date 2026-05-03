# 🛡️ PhishGuard AI — Real-Time Phishing Detection System

![Python](https://img.shields.io/badge/Python-3.11-blue?style=for-the-badge&logo=python)
![XGBoost](https://img.shields.io/badge/XGBoost-96.6%25_Accuracy-red?style=for-the-badge)
![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-ff4b4b?style=for-the-badge&logo=streamlit)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

> An AI-powered real-time phishing and social engineering detection system. Analyzes URLs and messages using Machine Learning before you click.

---

## 🎯 Live Demo
> Run locally — see Quick Start below

---

## ✨ Features

- 🔍 **Real-Time URL Scanner** — Analyzes 111 signals instantly
- 💬 **Message/Text Scanner** — Detects urgency language & brand impersonation
- 📊 **Risk Gauge** — Visual 0-100% threat score with color zones
- 🧠 **XGBoost ML Model** — Trained on 88,647 real phishing URLs
- ⚡ **NLP Urgency Detection** — Highlights manipulation keywords
- 🌐 **WHOIS Domain Age** — Flags newly registered suspicious domains
- 📄 **Report Export** — Download scan results as text file
- 🕐 **Scan History** — Tracks last 5 scans in session

---

## 📊 Model Performance

| Metric | Score |
|--------|-------|
| Accuracy | 96.61% |
| Precision | 94.93% |
| Recall | 95.29% |
| F1 Score | 95.11% |
| AUC-ROC | 99.44% |

---

## 🚀 Quick Start

### 1. Clone the repository
```bash
git clone https://github.com/mohammadshijan/PhishGuard-AI.git
cd PhishGuard-AI
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Download dataset & train model
```bash
# Download real phishing dataset (25MB)
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/GregaVrbancic/Phishing-Dataset/master/dataset_full.csv" -OutFile "data/phishing_dataset.csv"

# Train the model
python src/train_model.py
```

### 4. Launch dashboard
```bash
streamlit run main.py
```

Open browser at: **http://localhost:8501**

---

## 🏗️ Project Structure

---

## 🔬 Detection Signals (111 Features)

**URL Analysis:**
- Character counts (@, -, ., ?, =, #, %)
- Domain length, subdomain count
- HTTPS status, IP address detection
- Suspicious TLD detection (.xyz, .tk, .ml)
- Shortened URL detection (bit.ly, tinyurl)

**Message Analysis:**
- 27 urgency keyword patterns
- Brand impersonation detection
- Personal information requests
- Uppercase ratio analysis

---

## 🗺️ Roadmap

- [x] Phase 1 — Web Scanner
- [ ] Phase 2 — Chrome/Edge Browser Extension
- [ ] Phase 3 — FastAPI REST API
- [ ] Phase 4 — Real-time Threat Intelligence Feed

---

## 🛠️ Tech Stack

| Tool | Purpose |
|------|---------|
| XGBoost | ML Classification Engine |
| Streamlit | Web Dashboard |
| Plotly | Risk Gauge Charts |
| Pandas/NumPy | Data Processing |
| tldextract | Domain Parsing |
| python-whois | Domain Age Check |

---

## 👨‍💻 Author

**Mohammad Shijan**
- GitHub: [@mohammadshijan](https://github.com/mohammadshijan)

---

## 📄 License

MIT License — Free to use and modify.
