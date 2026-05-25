"""Supply Chain Sidecar — /assess API + Evidence Trail Dashboard."""

import os
import json
from flask import Flask, request, jsonify, render_template_string
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from agent.gemini_classifier import classify
from agent.enrichment import enrich, collect_signals
from agent.confidence import get_thresholds

app = Flask(__name__)
SIDECAR_MODE = os.getenv("SIDECAR_MODE", "balanced")

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100/day", "10/minute"],
    storage_uri="memory://",
)

HIGH_REP = {"lodash", "axios", "chalk", "express", "react", "typescript", "webpack", "babel"}
HIGH_REP_BLOCK_THRESHOLD = 0.40

DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Supply Chain Sidecar</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Courier New', monospace; background: #0d1117; color: #c9d1d9; min-height: 100vh; padding: 2rem; }
    h1 { color: #58a6ff; font-size: 1.2rem; letter-spacing: 0.1em; margin-bottom: 0.25rem; }
    .subtitle { color: #8b949e; font-size: 0.8rem; margin-bottom: 2rem; }
    .card { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 1.5rem; margin-bottom: 1.5rem; }
    .card h2 { font-size: 0.85rem; color: #8b949e; text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 1rem; }
    textarea { width: 100%; background: #0d1117; border: 1px solid #30363d; border-radius: 4px; color: #c9d1d9;
               font-family: 'Courier New', monospace; font-size: 0.85rem; padding: 0.75rem; resize: vertical; min-height: 200px; }
    textarea:focus { outline: none; border-color: #58a6ff; }
    button { background: #238636; color: #fff; border: none; border-radius: 4px; padding: 0.6rem 1.5rem;
             font-family: 'Courier New', monospace; font-size: 0.9rem; cursor: pointer; margin-top: 0.75rem; }
    button:hover { background: #2ea043; }
    .scenarios { display: flex; gap: 0.5rem; flex-wrap: wrap; margin-bottom: 0.75rem; }
    .scenario-btn { background: #21262d; border: 1px solid #30363d; color: #8b949e; border-radius: 4px;
                    padding: 0.3rem 0.75rem; font-size: 0.75rem; cursor: pointer; font-family: 'Courier New', monospace; }
    .scenario-btn:hover { border-color: #58a6ff; color: #58a6ff; }
    .verdict-block { display: flex; align-items: center; gap: 1rem; margin-bottom: 1rem; }
    .verdict { font-size: 1.5rem; font-weight: bold; padding: 0.4rem 1rem; border-radius: 4px; }
    .verdict.MALICIOUS { background: #3d1f1f; color: #f85149; border: 1px solid #f85149; }
    .verdict.SAFE { background: #1a2f1a; color: #3fb950; border: 1px solid #3fb950; }
    .verdict.UNKNOWN { background: #2d2a1f; color: #d29922; border: 1px solid #d29922; }
    .override-badge { background: #2d1f3d; color: #bc8cff; border: 1px solid #bc8cff;
                      border-radius: 4px; padding: 0.3rem 0.75rem; font-size: 0.75rem; }
    .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; }
    @media (max-width: 700px) { .two-col { grid-template-columns: 1fr; } }
    .signal-row { display: flex; justify-content: space-between; padding: 0.4rem 0;
                  border-bottom: 1px solid #21262d; font-size: 0.85rem; }
    .signal-row:last-child { border-bottom: none; }
    .signal-key { color: #8b949e; }
    .signal-val { color: #c9d1d9; }
    .signal-val.bad { color: #f85149; }
    .signal-val.good { color: #3fb950; }
    .conf-bar-wrap { background: #21262d; border-radius: 4px; height: 8px; margin-top: 0.5rem; }
    .conf-bar { height: 8px; border-radius: 4px; background: #58a6ff; }
    .conf-bar.high { background: #f85149; }
    .conf-bar.low { background: #3fb950; }
    .evidence { color: #e3b341; font-size: 0.85rem; margin-top: 0.75rem; padding: 0.75rem;
                background: #2d2a1f; border-radius: 4px; border-left: 3px solid #d29922; }
    .gemini-verdict { font-weight: bold; }
    .gemini-verdict.MALICIOUS { color: #f85149; }
    .gemini-verdict.SAFE { color: #3fb950; }
    .gemini-verdict.UNKNOWN { color: #d29922; }
    .error { color: #f85149; padding: 1rem; background: #3d1f1f; border-radius: 4px; }
    .halo-note { font-size: 0.75rem; color: #8b949e; margin-top: 0.5rem; font-style: italic; }
  </style>
</head>
<body>
<h1>⛓ SUPPLY CHAIN SIDECAR</h1>
<p class="subtitle">Gemini 2.5 Flash + Elastic MCP — Live Registry Evidence</p>

<div class="card">
  <h2>Assess Package</h2>
  <div class="scenarios">
    <span class="scenario-btn" onclick="loadScenario('axios_clean')">axios@1.14.0 clean</span>
    <span class="scenario-btn" onclick="loadScenario('axios_attack')">axios@1.14.1 attack</span>
    <span class="scenario-btn" onclick="loadScenario('lodash_clean')">lodash@4.17.21 clean</span>
    <span class="scenario-btn" onclick="loadScenario('lodash_attack')">lodash@4.17.22 hijack</span>
  </div>
  <form method="POST">
    <textarea name="manifest" id="manifest" placeholder='{"name": "lodash", "version": "4.17.22", ...}'>{{ manifest }}</textarea>
    <button type="submit">Assess →</button>
  </form>
</div>

{% if result %}
<div class="card">
  <h2>Verdict</h2>
  <div class="verdict-block">
    <div class="verdict {{ result.verdict }}">{{ result.verdict }}</div>
    {% if result.override_reason %}
    <div class="override-badge">⚡ MCP Override</div>
    {% endif %}
  </div>
  {% if result.override_reason %}
  <div class="halo-note">{{ result.override_reason }}</div>
  {% endif %}
</div>

<div class="two-col">
  <div class="card">
    <h2>Gemini Assessment</h2>
    <div style="display:flex; justify-content:space-between;">
      <span style="color:#8b949e;">verdict</span>
      <span class="gemini-verdict {{ result.gemini_verdict }}">{{ result.gemini_verdict or 'N/A' }}</span>
    </div>
    {% if result.override_reason %}
    <p class="halo-note" style="margin-top:0.75rem">
      Gemini assessed manifest content only. MCP registry evidence overrides this verdict for high-reputation packages.
    </p>
    {% endif %}
  </div>

  <div class="card">
    <h2>MCP Enrichment Confidence</h2>
    <div style="font-size:1.2rem; font-weight:bold; color:#58a6ff;">{{ "%.0f"|format(result.enrichment_confidence * 100) }}%</div>
    <div class="conf-bar-wrap">
      <div class="conf-bar {% if result.enrichment_confidence >= 0.6 %}high{% elif result.enrichment_confidence <= 0.2 %}low{% endif %}"
           style="width:{{ result.enrichment_confidence * 100 }}%"></div>
    </div>
    {% if result.evidence_summary %}
    <div class="evidence">{{ result.evidence_summary }}</div>
    {% endif %}
  </div>
</div>

{% if result.signals %}
<div class="card">
  <h2>Registry Signals — Elastic MCP</h2>
  {% for key, val in result.signals.items() %}
  <div class="signal-row">
    <span class="signal-key">{{ key }}</span>
    <span class="signal-val {% if val == false or val == 'missing' or val == 'unknown' %}bad{% elif val == true or val == 'before_publish' or val == 'oidc' %}good{% endif %}">
      {% if val is none %}—{% else %}{{ val }}{% endif %}
    </span>
  </div>
  {% endfor %}
</div>
{% endif %}
{% endif %}

{% if error %}
<div class="error">{{ error }}</div>
{% endif %}

<script>
const scenarios = {
  axios_clean: '{"name":"axios","version":"1.14.0","description":"Promise based HTTP client","scripts":{"test":"jest"},"dependencies":{"follow-redirects":"^1.15.6","form-data":"^4.0.0","proxy-from-env":"^1.1.0"},"maintainers":[{"name":"jasonsaayman"}],"license":"MIT"}',
  axios_attack: '{"name":"axios","version":"1.14.1","description":"Promise based HTTP client","scripts":{"test":"jest"},"dependencies":{"follow-redirects":"^1.15.6","form-data":"^4.0.0","proxy-from-env":"^1.1.0","plain-crypto-js":"^4.2.1"},"maintainers":[{"name":"jasonsaayman"}],"license":"MIT"}',
  lodash_clean: '{"name":"lodash","version":"4.17.21","description":"Lodash modular utilities.","scripts":{"test":"echo test"},"dependencies":{},"maintainers":[{"name":"jdalton"}],"license":"MIT"}',
  lodash_attack: '{"name":"lodash","version":"4.17.22","description":"Lodash modular utilities.","scripts":{"test":"echo test"},"dependencies":{},"maintainers":[{"name":"jdalton"}],"license":"MIT"}'
};
function loadScenario(id) {
  document.getElementById('manifest').value = JSON.stringify(JSON.parse(scenarios[id]), null, 2);
}
</script>
</body>
</html>
"""


@app.route("/", methods=["GET", "POST"])
@limiter.exempt
def dashboard():
    result = None
    error = None
    manifest_str = ""
    if request.method == "POST":
        manifest_str = request.form.get("manifest", "").strip()
        if manifest_str:
            try:
                manifest = json.loads(manifest_str)
                name = manifest.get("name", "unknown")
                thresholds = get_thresholds(SIDECAR_MODE)
                if name in HIGH_REP:
                    initial = classify(manifest)
                    collected = collect_signals(manifest)
                    override = collected["enrichment_confidence"] >= HIGH_REP_BLOCK_THRESHOLD
                    verdict = "MALICIOUS" if override else "SAFE"
                    result = {
                        "verdict": verdict,
                        "confidence": collected["enrichment_confidence"] if override else 1.0 - collected["enrichment_confidence"],
                        "enriched": True,
                        "signals": collected["signals"],
                        "enrichment_confidence": collected["enrichment_confidence"],
                        "evidence_summary": collected["evidence_summary"],
                        "override_reason": "high-reputation package — MCP evidence takes precedence" if override else None,
                        "gemini_verdict": initial["verdict"],
                    }
                else:
                    initial = classify(manifest)
                    p_mal = initial["p_malicious"]
                    if p_mal >= thresholds["block"]:
                        result = {"verdict": "MALICIOUS", "confidence": p_mal, "enriched": False,
                                  "evidence_summary": initial["raw"], "gemini_verdict": initial["verdict"],
                                  "enrichment_confidence": 0, "signals": {}, "override_reason": None}
                    elif p_mal < thresholds["escalate"]:
                        result = {"verdict": "SAFE", "confidence": 1.0 - p_mal, "enriched": False,
                                  "evidence_summary": "Below escalation threshold.", "gemini_verdict": initial["verdict"],
                                  "enrichment_confidence": 0, "signals": {}, "override_reason": None}
                    else:
                        enriched = enrich(manifest, initial)
                        enriched["verdict"] = "MALICIOUS" if enriched["confidence"] >= thresholds["block"] else "SAFE"
                        enriched["gemini_verdict"] = initial["verdict"]
                        enriched.setdefault("override_reason", None)
                        result = enriched
            except json.JSONDecodeError:
                error = "Invalid JSON — check the manifest format."
            except Exception as e:
                error = f"Assessment failed: {e}"
    return render_template_string(DASHBOARD_TEMPLATE, result=result, error=error, manifest=manifest_str)


@app.route("/assess", methods=["POST"])
def assess():
    data = request.get_json(force=True)
    manifest = data.get("manifest") or {}
    if not manifest:
        manifest = {"name": data.get("name", "unknown"), "version": data.get("version", "unknown")}

    name = manifest.get("name", "unknown")
    thresholds = get_thresholds(SIDECAR_MODE)

    if name in HIGH_REP:
        initial = classify(manifest)
        collected = collect_signals(manifest)
        override = collected["enrichment_confidence"] >= HIGH_REP_BLOCK_THRESHOLD
        verdict = "MALICIOUS" if override else "SAFE"
        return jsonify({
            "verdict": verdict,
            "confidence": collected["enrichment_confidence"] if override else 1.0 - collected["enrichment_confidence"],
            "enriched": True,
            "signals": collected["signals"],
            "enrichment_confidence": collected["enrichment_confidence"],
            "evidence_summary": collected["evidence_summary"],
            "override_reason": "high-reputation package — MCP evidence takes precedence" if override else None,
            "gemini_verdict": initial["verdict"],
        })

    initial = classify(manifest)
    p_mal = initial["p_malicious"]

    if p_mal >= thresholds["block"]:
        return jsonify({"verdict": "MALICIOUS", "confidence": p_mal, "enriched": False,
                        "evidence_summary": initial["raw"]})

    if p_mal < thresholds["escalate"]:
        return jsonify({"verdict": "SAFE", "confidence": 1.0 - p_mal, "enriched": False,
                        "evidence_summary": "Below escalation threshold."})

    result = enrich(manifest, initial)
    result["verdict"] = "MALICIOUS" if result["confidence"] >= thresholds["block"] else "SAFE"
    return jsonify(result)


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "mode": SIDECAR_MODE})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 8080)))
