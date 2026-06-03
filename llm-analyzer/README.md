# LLM Analyzer Module

**Maintainer:** 楊絜安  
**Role:** Prompt engineering + LLM integration — converts feature JSON into a natural language risk explanation.

---

## Files

| File | Description |
|------|-------------|
| `analyzer.py` | Core module — provider factory, prompt builder, response parser |
| `tests/test_analyzer.py` | Unit tests for parsing and mock provider |

---

## How to Switch LLM Provider

Set env var in your `.env`:

```env
# Use OpenAI (requires API key)
LLM_PROVIDER=openai
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-4o-mini

# Use local Ollama (no key needed)
LLM_PROVIDER=ollama
OLLAMA_MODEL=llama3

# Use mock (for testing)
LLM_PROVIDER=mock
```

---

## How to Add a New Provider

1. Subclass `BaseLLMProvider` in `analyzer.py`
2. Implement the `complete(system_prompt, user_prompt) -> str` method
3. Register it in `get_provider()` factory

---

## How to Modify the Prompt

Edit `SYSTEM_PROMPT` in `analyzer.py`. The output format parser (`parse_llm_response`) expects:

```
RISK_LEVEL: High
EXPLANATION: ...
ATTACK_GOAL: ...
RECOMMENDATION: ...
CONFIDENCE: High
```

---

## Run Tests

```bash
cd llm-analyzer
pytest tests/ -v
```
