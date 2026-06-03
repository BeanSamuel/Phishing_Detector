# LLM-Based Phishing Website Detection and Explanation System

> **Course:** LLM Applications in Cybersecurity  
> **Group:** 120 | **Members:** 趙啟翔、吳畬、譚天皓、楊絜安

---

## 🗂 Repository Structure

```
phishing-detector/
├── frontend/          # 👤 趙啟翔 — Gradio UI + demo interface
├── backend/           # 👤 吳畬 — FastAPI orchestration server
├── feature-extractor/ # 👤 譚天皓 — URL heuristic feature extraction module
├── llm-analyzer/      # 👤 楊絜安 — LLM prompt engineering & analysis engine
└── docs/              # Shared documentation
```

---

## 🚀 Quick Start (Full Stack)

### Prerequisites
```bash
pip install -r requirements.txt
```

### Run All Services
```bash
# Terminal 1 — Backend API
cd backend && uvicorn main:app --reload --port 8000

# Terminal 2 — Frontend UI
cd frontend && python app.py
```

Visit: `http://localhost:7860`

---

## 🔗 Module Integration Flow

```
User Input (URL)
     ↓
[Frontend - Gradio]     port 7860
     ↓  POST /analyze
[Backend - FastAPI]     port 8000
     ↓
[Feature Extractor]     (Python module)
     ↓  JSON features
[LLM Analyzer]          (OpenAI / Ollama)
     ↓
Risk Report → Frontend
```

---

## 🧩 GitHub Collaboration Guide

Each member works in their own folder. To collaborate:

```bash
# Clone
git clone https://github.com/YOUR_ORG/phishing-detector.git

# Create your branch
git checkout -b feature/frontend-ui      # 趙啟翔
git checkout -b feature/backend-api      # 吳畬
git checkout -b feature/feature-extractor # 譚天皓
git checkout -b feature/llm-analyzer     # 楊絜安

# Work in your module folder only
# Submit Pull Request → main when ready
```

---

## ⚙️ Environment Variables

Create a `.env` file in root:
```env
OPENAI_API_KEY=your_key_here
LLM_PROVIDER=openai        # or "ollama"
OLLAMA_BASE_URL=http://localhost:11434
BACKEND_URL=http://localhost:8000
```

---

## 📊 Evaluation

See `docs/evaluation_plan.md` for the testing methodology using PhishTank + Tranco datasets.
