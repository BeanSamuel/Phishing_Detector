"""
Backend API Server
==================
Maintainer: 吳畬
Responsibility: FastAPI orchestration layer.
Routes requests between frontend, feature extractor, and LLM analyzer.

Design principle:
- Each route is thin: validate input → call modules → return response.
- Add new endpoints here as the system grows (batch analysis, history, etc.).
- All business logic lives in the feature-extractor and llm-analyzer modules.
"""

from __future__ import annotations
import sys
import os
import time
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator

# Add sibling module paths
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "feature-extractor"))
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "llm-analyzer"))

from extractor import extract_features          # noqa: E402
from analyzer import LLMAnalyzer               # noqa: E402

# ── App Setup ─────────────────────────────────────────────────────────────────

app = FastAPI(
    title="PhishGuard API",
    description="LLM-based phishing detection and explanation system",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # Restrict in production
    allow_methods=["*"],
    allow_headers=["*"],
)

# Singleton analyzer (avoids re-creating provider on every request)
_analyzer: Optional[LLMAnalyzer] = None


def get_analyzer() -> LLMAnalyzer:
    global _analyzer
    if _analyzer is None:
        _analyzer = LLMAnalyzer()
    return _analyzer


# ── Request / Response Schemas ────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def url_must_not_be_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("URL cannot be empty")
        if len(v) > 2048:
            raise ValueError("URL too long (max 2048 chars)")
        return v


class FeatureItem(BaseModel):
    name: str
    value: bool | int | float | str
    risk_weight: float
    description: str


class AnalyzeResponse(BaseModel):
    url: str
    risk_level: str                    # Low / Medium / High
    total_risk_score: float            # 0–100
    features: list[FeatureItem]
    llm_explanation: str
    attack_goal: str
    recommendation: str
    confidence: str
    processing_time_ms: int


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {"status": "ok", "service": "PhishGuard API v0.1.0"}


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze_url(request: AnalyzeRequest):
    """
    Full phishing analysis pipeline:
    1. Extract heuristic features from URL
    2. Compute risk score
    3. Send to LLM for natural language explanation
    4. Return combined report
    """
    start = time.perf_counter()

    # Step 1: Feature extraction
    try:
        extraction = extract_features(request.url)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Feature extraction failed: {e}")

    # Step 2: LLM analysis
    try:
        analyzer = get_analyzer()
        analysis = analyzer.analyze(
            url=extraction.url,
            features=[f.__dict__ for f in extraction.features],
            risk_score=extraction.total_risk_score,
        )
        print("=" * 40)
        print("RAW LLM RESPONSE:")
        print(analysis.raw_response)
        print("=" * 40)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"LLM analysis failed: {e}")

    elapsed_ms = int((time.perf_counter() - start) * 1000)

    return AnalyzeResponse(
        url=extraction.url,
        risk_level=extraction.risk_level,
        total_risk_score=extraction.total_risk_score,
        features=[
            FeatureItem(
                name=f.name,
                value=f.value,
                risk_weight=f.risk_weight,
                description=f.description,
            )
            for f in extraction.features
        ],
        llm_explanation=analysis.explanation,
        attack_goal=analysis.attack_goal,
        recommendation=analysis.recommendation,
        confidence=analysis.confidence,
        processing_time_ms=elapsed_ms,
    )


@app.post("/features-only")
def features_only(request: AnalyzeRequest):
    """
    Extract features without calling LLM.
    Useful for fast batch pre-screening or frontend previews.
    """
    try:
        report = extract_features(request.url)
        return report.to_dict()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Extension Points ──────────────────────────────────────────────────────────
# 
# To add batch analysis:
#   @app.post("/analyze/batch")
#   def analyze_batch(requests: list[AnalyzeRequest]): ...
#
# To add history/logging:
#   Use a SQLite database with SQLModel or raw sqlite3
#
# To add authentication:
#   from fastapi.security import APIKeyHeader
#   api_key_header = APIKeyHeader(name="X-API-Key")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
