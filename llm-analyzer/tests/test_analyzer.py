"""
Unit Tests — LLM Analyzer
Maintainer: 楊絜安
Run: pytest llm-analyzer/tests/ -v
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from analyzer import (
    LLMAnalyzer,
    MockProvider,
    AnalysisPromptBuilder,
    parse_llm_response,
)


def test_mock_provider_returns_result():
    analyzer = LLMAnalyzer(provider=MockProvider())
    result = analyzer.analyze(
        url="http://evil.com",
        features=[{"name": "ip_in_url", "value": True, "risk_weight": 0.9, "description": "IP"}],
        risk_score=55.0,
    )
    assert result.risk_level in ("High", "Medium", "Low")
    assert len(result.explanation) > 5
    assert len(result.recommendation) > 5


def test_parse_llm_response_complete():
    raw = (
        "RISK_LEVEL: High\n"
        "EXPLANATION: Step 1 — IP detected. Step 2 — long URL.\n"
        "ATTACK_GOAL: Steal PayPal credentials\n"
        "RECOMMENDATION: Do not enter any information.\n"
        "CONFIDENCE: High\n"
    )
    result = parse_llm_response(raw)
    assert result.risk_level == "High"
    assert "IP" in result.explanation
    assert result.attack_goal == "Steal PayPal credentials"
    assert result.confidence == "High"


def test_parse_llm_response_missing_fields():
    raw = "RISK_LEVEL: Low\nEXPLANATION: Seems fine."
    result = parse_llm_response(raw)
    assert result.risk_level == "Low"
    assert result.attack_goal == "Unknown"


def test_prompt_builder_includes_triggered_features():
    features = [
        {"name": "ip_in_url", "value": True, "risk_weight": 0.9, "description": "IP"},
        {"name": "url_length", "value": 30, "risk_weight": 0.0, "description": "Short"},
    ]
    prompt = AnalysisPromptBuilder.build("http://1.2.3.4/", features, 45.0)
    assert "ip_in_url" in prompt
    assert "45.0" in prompt


def test_analyzer_to_dict():
    analyzer = LLMAnalyzer(provider=MockProvider())
    result = analyzer.analyze("http://x.com", [], 10.0)
    d = result.to_dict()
    assert "risk_level" in d
    assert "explanation" in d
    assert "raw_response" not in d   # Should not expose raw output in API response


def test_gemini_provider_mocked(monkeypatch):
    from unittest.mock import MagicMock
    import analyzer

    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.choices = [
        MagicMock(message=MagicMock(content="RISK_LEVEL: Low\nEXPLANATION: Mocked Gemini\nATTACK_GOAL: None\nRECOMMENDATION: Safe\nCONFIDENCE: High"))
    ]
    mock_client.chat.completions.create.return_value = mock_response

    monkeypatch.setenv("GEMINI_API_KEY", "dummy_key")
    import openai
    monkeypatch.setattr(openai, "OpenAI", lambda *args, **kwargs: mock_client)

    provider = analyzer.GeminiProvider()
    res = provider.complete("system_prompt", "user_prompt")

    assert "Mocked Gemini" in res
    mock_client.chat.completions.create.assert_called_once_with(
        model="gemini-2.5-flash",
        messages=[
            {"role": "system", "content": "system_prompt"},
            {"role": "user", "content": "user_prompt"},
        ],
        temperature=0.2,
    )
