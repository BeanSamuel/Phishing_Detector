# Backend API Module

**Maintainer:** 吳畬  
**Role:** FastAPI orchestration server — connects frontend, feature extractor, and LLM analyzer.

---

## Files

| File | Description |
|------|-------------|
| `main.py` | FastAPI app with all routes |
| `tests/test_api.py` | Integration tests using TestClient |

---

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Service status |
| GET | `/health` | Health check |
| POST | `/analyze` | Full analysis (features + LLM) |
| POST | `/features-only` | Feature extraction only (no LLM) |

---

## Run Locally

```bash
cd backend
uvicorn main:app --reload --port 8000
```

Interactive API docs: `http://localhost:8000/docs`

---

## Run Tests

```bash
cd backend
pytest tests/ -v
```

---

## Extension Points

See comments at the bottom of `main.py` for how to add:
- Batch analysis endpoint
- Request history / logging
- API key authentication
