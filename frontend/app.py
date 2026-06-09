"""
Frontend — Gradio UI
====================
Maintainer: 趙啟翔
Responsibility: User-facing interface using Gradio.
Sends URLs to the backend and displays the phishing risk report.

Design principle:
- UI logic only — no analysis logic here.
- Backend URL is configurable via BACKEND_URL env var.
- To extend: add new Gradio components or tabs without touching other modules.
"""

from __future__ import annotations
import os
import json
import httpx
import gradio as gr
from dotenv import load_dotenv

load_dotenv()

BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")


# ── API Client ────────────────────────────────────────────────────────────────

def call_analyze(url: str) -> dict:
    """POST /analyze to backend. Returns JSON dict or raises exception."""
    with httpx.Client(timeout=30.0) as client:
        response = client.post(f"{BACKEND_URL}/analyze", json={"url": url})
        response.raise_for_status()
        return response.json()


# ── Risk Styling ──────────────────────────────────────────────────────────────

RISK_COLORS = {
    "High":   "#FF4444",
    "Medium": "#FF9800",
    "Low":    "#4CAF50",
}

RISK_ICONS = {
    "High":   "🔴",
    "Medium": "🟡",
    "Low":    "🟢",
}


def format_features_html(features: list[dict]) -> str:
    """Render extracted features as a styled HTML table."""
    rows = ""
    for f in sorted(features, key=lambda x: -x["risk_weight"]):
        color = "#FF4444" if f["risk_weight"] >= 0.7 else \
                "#FF9800" if f["risk_weight"] >= 0.3 else "#4CAF50"
        icon = "⚠️" if f["risk_weight"] > 0 else "✅"
        rows += f"""
        <tr>
          <td style="padding:6px 10px; font-family:monospace; font-size:13px">{icon} {f['name']}</td>
          <td style="padding:6px 10px; color:{color}; font-weight:bold">{f['value']}</td>
          <td style="padding:6px 10px; color:#666; font-size:12px">{f['description']}</td>
        </tr>
        """
    return f"""
    <table style="width:100%; border-collapse:collapse; border:1px solid #ddd; border-radius:8px; overflow:hidden">
      <thead>
        <tr style="background:#f5f5f5">
          <th style="padding:8px 10px; text-align:left">Feature</th>
          <th style="padding:8px 10px; text-align:left">Value</th>
          <th style="padding:8px 10px; text-align:left">Detail</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
    """


def format_risk_badge(risk_level: str, score: float) -> str:
    color = RISK_COLORS.get(risk_level, "#888")
    icon = RISK_ICONS.get(risk_level, "⚪")
    return f"""
    <div style="display:flex; align-items:center; gap:16px; padding:16px;
                background:{color}22; border:2px solid {color};
                border-radius:12px; margin-bottom:12px">
      <span style="font-size:40px">{icon}</span>
      <div>
        <div style="font-size:24px; font-weight:bold; color:{color}">{risk_level} Risk</div>
        <div style="font-size:14px; color:#555">Score: {score:.1f} / 100</div>
      </div>
    </div>
    """


# ── Main Analysis Function ────────────────────────────────────────────────────

def analyze(url: str):
    """Called when user clicks Analyze. Returns all output component values."""
    url = url.strip()
    if not url:
        return (
            "<p style='color:red'>Please enter a URL.</p>",
            "", "", "", "", ""
        )

    try:
        data = call_analyze(url)
    except httpx.HTTPStatusError as e:
        return (
            f"<p style='color:red'>API Error {e.response.status_code}: {e.response.text}</p>",
            "", "", "", "", ""
        )
    except httpx.ConnectError:
        return (
            "<p style='color:red'>Cannot connect to backend. Is it running at "
            f"<code>{BACKEND_URL}</code>?</p>",
            "", "", "", "", ""
        )
    except Exception as e:
        return (
            f"<p style='color:red'>Unexpected error: {e}</p>",
            "", "", "", "", ""
        )

    risk_badge = format_risk_badge(data["risk_level"], data["total_risk_score"])
    features_html = format_features_html(data["features"])

    return (
        risk_badge,
        features_html,
        data.get("llm_explanation", ""),
        data.get("attack_goal", ""),
        data.get("recommendation", ""),
        f"Confidence: {data.get('confidence', 'N/A')} | "
        f"Processing: {data.get('processing_time_ms', '?')}ms",
    )


# ── Example URLs ──────────────────────────────────────────────────────────────

EXAMPLES = [
    ["https://www.google.com"],
    ["http://https-paypal-login.verify-account-update.com/login.php"],
    ["http://125.98.3.123/secure/login.html"],
    ["https://bit.ly/3xPhish"],
    ["http://secure-paypal.login.verify.update.com:8080/account@phish"],
]


# ── Gradio UI ─────────────────────────────────────────────────────────────────

def build_ui() -> gr.Blocks:
    with gr.Blocks(
        title="PhishGuard — LLM Phishing Detector",
    ) as demo:

        gr.HTML("""
        <div class="main-title">
          <h1>🛡️ PhishGuard</h1>
        </div>
        <div class="subtitle">
          LLM-Based Phishing Website Detection &amp; Explanation System<br>
          <small>Group 120 | LLM Applications in Cybersecurity</small>
        </div>
        """)

        with gr.Row():
            url_input = gr.Textbox(
                label="Enter URL to Analyze",
                placeholder="e.g. https://suspicious-login.com/verify",
                scale=5,
            )
            analyze_btn = gr.Button("🔍 Analyze", variant="primary", scale=1)

        gr.Examples(examples=EXAMPLES, inputs=[url_input], label="Try these examples")

        # ── Output Section ────────────────────────────────────────────────────
        risk_output = gr.HTML(label="Risk Assessment")

        with gr.Tabs():
            with gr.Tab("📋 Feature Analysis"):
                features_output = gr.HTML(label="Extracted Features")

            with gr.Tab("🤖 LLM Explanation"):
                explanation_output = gr.Textbox(
                    label="AI Reasoning",
                    lines=5,
                    interactive=False,
                )
                with gr.Row():
                    goal_output = gr.Textbox(label="Inferred Attack Goal", interactive=False)
                    rec_output = gr.Textbox(label="Recommendation", interactive=False)

        status_output = gr.Textbox(label="", interactive=False, show_label=False)

        # ── Event Binding ─────────────────────────────────────────────────────
        outputs = [risk_output, features_output, explanation_output,
                   goal_output, rec_output, status_output]

        analyze_btn.click(fn=analyze, inputs=[url_input], outputs=outputs)
        url_input.submit(fn=analyze, inputs=[url_input], outputs=outputs)

        # ── Footer ────────────────────────────────────────────────────────────
        gr.HTML("""
        <hr style="margin-top:32px"/>
        <p style="text-align:center; color:#aaa; font-size:12px">
          PhishGuard PoC | Course: LLM Applications in Cybersecurity
          | Members: 趙啟翔, 吳畬, 譚天皓, 楊絜安
        </p>
        """)

    return demo


# ── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    demo = build_ui()
    demo.launch(
        server_name="0.0.0.0",
        server_port=int(os.getenv("GRADIO_PORT", 7860)),
        share=False,
        theme=gr.themes.Soft(primary_hue="red"),
        css="""
        .main-title { text-align: center; margin-bottom: 8px; }
        .subtitle { text-align: center; color: #666; margin-bottom: 24px; }
        """,
    )
