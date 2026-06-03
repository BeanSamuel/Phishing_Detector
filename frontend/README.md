# Frontend Module

**Maintainer:** 趙啟翔  
**Role:** Gradio-based user interface — collects URL input, displays risk assessment and LLM explanation.

---

## Files

| File | Description |
|------|-------------|
| `app.py` | Gradio UI — all interface logic |

---

## Run Locally

Make sure the backend is running first, then:

```bash
cd frontend
python app.py
```

Open: `http://localhost:7860`

---

## Configuration

| Env Var | Default | Description |
|---------|---------|-------------|
| `BACKEND_URL` | `http://localhost:8000` | Backend API address |
| `GRADIO_PORT` | `7860` | Port for Gradio server |

---

## How to Extend

- **Add a new tab:** Create a new `gr.Tab()` block inside `build_ui()`
- **Add batch analysis:** Add a `gr.File()` input that accepts CSV of URLs
- **Add history:** Use Gradio `State` to store past analyses in the session
- **Change theme:** Edit `gr.themes.Soft(primary_hue=...)` in `build_ui()`

---

## UI Structure

```
PhishGuard
├── URL Input + Analyze Button
├── Examples
├── Risk Badge (High/Medium/Low + score)
└── Tabs
    ├── Feature Analysis (HTML table)
    └── LLM Explanation
        ├── AI Reasoning
        ├── Attack Goal
        └── Recommendation
```
