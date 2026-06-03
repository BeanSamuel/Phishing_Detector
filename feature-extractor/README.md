# Feature Extractor Module

**Maintainer:** 譚天皓  
**Role:** URL heuristic feature extraction — converts a raw URL into a structured JSON risk report.

---

## Files

| File | Description |
|------|-------------|
| `extractor.py` | Core module — all feature logic lives here |
| `tests/test_extractor.py` | Unit + integration tests |

---

## How to Add a New Feature

1. Write a function with this signature:
   ```python
   def check_my_feature(parsed: ParseResult, raw_url: str) -> FeatureResult:
       ...
       return FeatureResult(name="my_feature", value=..., risk_weight=0.0–1.0, description="...")
   ```

2. Register it at the bottom of `extractor.py`:
   ```python
   FEATURE_REGISTRY: list[Callable] = [
       ...
       check_my_feature,   # ← add here
   ]
   ```

That's it — the scoring engine picks it up automatically.

---

## Output Example

```json
{
  "url": "http://https-paypal-login.verify-account-update.com/login.php",
  "risk_level": "High",
  "total_risk_score": 68.4,
  "features": [
    { "name": "ip_in_url",        "value": false, "risk_weight": 0.0 },
    { "name": "url_length",       "value": 62,    "risk_weight": 0.4 },
    { "name": "subdomain_count",  "value": 3,     "risk_weight": 0.75 },
    { "name": "dash_in_domain",   "value": true,  "risk_weight": 0.55 },
    { "name": "https_keyword_abuse", "value": "https, login, verify, account, update", "risk_weight": 0.5 }
  ]
}
```

---

## Run Tests

```bash
cd feature-extractor
pytest tests/ -v
```
