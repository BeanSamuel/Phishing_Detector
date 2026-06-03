"""
LLM Analyzer Module
===================
Maintainer: 楊絜安
Responsibility: Prompt engineering + LLM integration.
Converts structured feature JSON → natural language risk explanation.

Design principle:
- Provider-agnostic: swap between OpenAI and Ollama via env var.
- To change the analysis style: edit SYSTEM_PROMPT or AnalysisPromptBuilder.
- To add a new LLM provider: implement the BaseLLMProvider interface.
"""

from __future__ import annotations
import json
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from dotenv import load_dotenv

load_dotenv()

# ── Data Models ───────────────────────────────────────────────────────────────

@dataclass
class AnalysisResult:
    risk_level: str          # High / Medium / Low
    explanation: str         # Step-by-step reasoning
    attack_goal: str         # Inferred intent
    recommendation: str      # User-facing advice
    confidence: str          # High / Medium / Low
    raw_response: str = ""   # Full LLM output (for debugging)

    def to_dict(self) -> dict:
        return {
            "risk_level": self.risk_level,
            "explanation": self.explanation,
            "attack_goal": self.attack_goal,
            "recommendation": self.recommendation,
            "confidence": self.confidence,
        }


# ── System Prompt ─────────────────────────────────────────────────────────────
# Edit this to change the LLM's persona and output format.

SYSTEM_PROMPT = """You are PhishGuard, an expert cybersecurity analyst specializing in phishing detection.

Your task: Analyze a URL and its extracted heuristic features to determine if the site is a phishing threat.

Use Chain-of-Thought (CoT) reasoning: think step-by-step through each feature before reaching a conclusion.

You MUST respond in the following exact format (no extra text outside this structure):

RISK_LEVEL: [High/Medium/Low]
EXPLANATION: [Step-by-step reasoning. Reference specific features from the input. Be specific, not generic.]
ATTACK_GOAL: [What credential/data is the attacker likely targeting?]
RECOMMENDATION: [Clear, actionable advice for the user — what should they do right now?]
CONFIDENCE: [High/Medium/Low — how confident are you in this assessment?]

Rules:
- Never hallucinate features not present in the JSON input.
- If risk is Low, still explain WHY it appears safe.
- Keep EXPLANATION under 120 words.
- Keep RECOMMENDATION under 40 words.
"""


# ── Prompt Builder ────────────────────────────────────────────────────────────

class AnalysisPromptBuilder:
    """
    Constructs the user-turn prompt from URL + feature data.
    Extend this class to add richer context (e.g., WHOIS data, screenshot).
    """

    @staticmethod
    def build(url: str, features: list[dict], risk_score: float) -> str:
        # Only include triggered (non-zero) features to keep context focused
        triggered = [f for f in features if f.get("risk_weight", 0) > 0]
        safe = [f for f in features if f.get("risk_weight", 0) == 0]

        prompt = f"""Analyze this URL for phishing risk.

URL: {url}

Pre-computed Risk Score: {risk_score:.1f}/100

Triggered Risk Features (suspicious):
{json.dumps(triggered, indent=2)}

Clean Features (not triggered):
{json.dumps([f["name"] for f in safe], indent=2)}

Provide your analysis following the required format exactly.
"""
        return prompt


# ── LLM Provider Interface ────────────────────────────────────────────────────

class BaseLLMProvider(ABC):
    """Implement this interface to add a new LLM backend."""

    @abstractmethod
    def complete(self, system_prompt: str, user_prompt: str) -> str:
        """Returns the raw text response from the model."""
        ...


class OpenAIProvider(BaseLLMProvider):
    """OpenAI GPT backend (gpt-4o-mini by default for cost efficiency)."""

    def __init__(self, model: str = "gpt-4o-mini"):
        from openai import OpenAI
        self.client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        self.model = model

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.2,   # Low temp for consistent structured output
            max_tokens=600,
        )
        return response.choices[0].message.content


class OllamaProvider(BaseLLMProvider):
    """Local Ollama backend — no API key required."""

    def __init__(self, model: str = "llama3"):
        import ollama as ollama_lib
        self.client = ollama_lib
        self.model = model

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        response = self.client.chat(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        )
        return response["message"]["content"]


class MockProvider(BaseLLMProvider):
    """Mock provider for testing without API keys."""

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        return (
            "RISK_LEVEL: High\n"
            "EXPLANATION: Mock analysis — IP address detected, suspicious subdomains, keyword abuse.\n"
            "ATTACK_GOAL: Credential harvesting (mock)\n"
            "RECOMMENDATION: Do not enter any personal information on this site.\n"
            "CONFIDENCE: High"
        )


def get_provider() -> BaseLLMProvider:
    """
    Factory: selects LLM provider based on LLM_PROVIDER env var.
    Add new providers here to extend the system.
    """
    provider = os.getenv("LLM_PROVIDER", "mock").lower()
    if provider == "openai":
        model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        return OpenAIProvider(model=model)
    elif provider == "ollama":
        model = os.getenv("OLLAMA_MODEL", "llama3")
        return OllamaProvider(model=model)
    else:
        return MockProvider()


# ── Response Parser ───────────────────────────────────────────────────────────

def parse_llm_response(raw: str) -> AnalysisResult:
    """
    Parse structured LLM output into an AnalysisResult.
    Robust to minor formatting variations.
    """
    def extract(key: str) -> str:
        for line in raw.splitlines():
            if line.strip().upper().startswith(key + ":"):
                return line.split(":", 1)[1].strip()
        return "Unknown"

    return AnalysisResult(
        risk_level=extract("RISK_LEVEL"),
        explanation=extract("EXPLANATION"),
        attack_goal=extract("ATTACK_GOAL"),
        recommendation=extract("RECOMMENDATION"),
        confidence=extract("CONFIDENCE"),
        raw_response=raw,
    )


# ── Main Analyzer ─────────────────────────────────────────────────────────────

class LLMAnalyzer:
    """
    Orchestrates prompt building, LLM call, and response parsing.
    
    Usage:
        analyzer = LLMAnalyzer()
        result = analyzer.analyze(url, features, risk_score)
    """

    def __init__(self, provider: BaseLLMProvider | None = None):
        self.provider = provider or get_provider()
        self.prompt_builder = AnalysisPromptBuilder()

    def analyze(self, url: str, features: list[dict], risk_score: float) -> AnalysisResult:
        user_prompt = self.prompt_builder.build(url, features, risk_score)
        raw = self.provider.complete(SYSTEM_PROMPT, user_prompt)
        return parse_llm_response(raw)


# ── CLI Quick Test ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    sample_features = [
        {"name": "url_length", "value": 85, "risk_weight": 0.7, "description": "Long URL"},
        {"name": "subdomain_count", "value": 4, "risk_weight": 0.75, "description": "4 subdomains"},
        {"name": "dash_in_domain", "value": True, "risk_weight": 0.55, "description": "Dash in domain"},
        {"name": "https_keyword_abuse", "value": "https, login, verify", "risk_weight": 0.5, "description": "Keyword abuse"},
        {"name": "ip_in_url", "value": False, "risk_weight": 0.0, "description": "No IP"},
    ]
    analyzer = LLMAnalyzer()
    result = analyzer.analyze(
        url="http://https-paypal-login.verify-account-update.com/login.php",
        features=sample_features,
        risk_score=68.4,
    )
    print(f"Risk Level  : {result.risk_level}")
    print(f"Confidence  : {result.confidence}")
    print(f"Explanation : {result.explanation}")
    print(f"Goal        : {result.attack_goal}")
    print(f"Advice      : {result.recommendation}")
