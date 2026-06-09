"""
Integration Tests — Backend API
Maintainer: 吳畬
Run: pytest backend/tests/ -v
Requires: pytest-asyncio, httpx
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "feature-extractor"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "llm-analyzer"))

import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def test_root():
    r = client.get("/")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_health():
    r = client.get("/health")
    assert r.status_code == 200


def test_analyze_returns_valid_structure():
    r = client.post("/analyze", json={"url": "https://www.google.com"})
    assert r.status_code == 200
    data = r.json()
    assert "risk_level" in data
    assert "total_risk_score" in data
    assert "features" in data
    assert "llm_explanation" in data
    assert "recommendation" in data


def test_analyze_empty_url_rejected():
    r = client.post("/analyze", json={"url": ""})
    assert r.status_code == 422


def test_features_only_endpoint():
    r = client.post("/features-only", json={"url": "http://125.98.3.123/login"})
    assert r.status_code == 200
    data = r.json()
    assert "features" in data
    assert "risk_level" in data


def test_risk_score_in_range():
    r = client.post("/analyze", json={"url": "https://example.com"})
    assert r.status_code == 200
    score = r.json()["total_risk_score"]
    assert 0 <= score <= 100
