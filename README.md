# 🛡️ Sentrix — Hybrid ML-Powered Web Application Firewall

> Intelligent HTTP request inspection combining Rule Engine + DistilBERT Transformer

[![Python](https://img.shields.io/badge/Python-3.11-blue)]()
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111-green)]()
[![DistilBERT](https://img.shields.io/badge/Model-DistilBERT-orange)]()

## Architecture
Client Request → Parser → Normalizer → Formatter → Rule Engine (regex) → DistilBERT Classifier → Decision Engine → allow / block / flag → SQLite Logger → FastAPI Response


## Attack Classes
| Class | Description |
|---|---|
| benign | Safe request |
| sqli | SQL Injection |
| xss | Cross-Site Scripting |
| traversal | Path Traversal |
| cmdi | Command Injection |

## Quick Start
```bash
pip install -r requirements.txt
python src/preprocessing/augmentor.py
python src/models/train.py
uvicorn api.app:app --reload --port 8000
streamlit run dashboard/streamlit_app.py
python demo_app/app.py
```

## Build Progress
- [x] Preprocessing pipeline
- [x] Rule engine
- [x] ML models
- [x] Decision engine
- [x] FastAPI service
- [x] Streamlit dashboard
- [x] Demo app
- [x] Docker
