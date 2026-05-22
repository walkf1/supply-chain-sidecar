"""Supply Chain Sidecar — /assess API.

Two detection paths:
  High-reputation packages  → MCP evidence overrides Gemini (collect_signals only)
  Everything else           → Gemini score drives escalation to full enrich()
"""

import os
import json
from flask import Flask, request, jsonify, render_template_string
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from agent.gemini_classifier import classify
from agent.enrichment import enrich, collect_signals
from agent.confidence import get_thresholds
from dashboard.app import TEMPLATE as DASHBOARD_TEMPLATE

app = Flask(__name__)
SIDECAR_MODE = os.getenv("SIDECAR_MODE", "balanced")

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100/day", "10/minute"],
    storage_uri="memory://",
)

# Packages targeted by version-jump attacks — MCP evidence always runs
HIGH_REP = {"lodash", "axios", "chalk", "express", "react", "typescript", "webpack", "babel"}

# In Càrn's full pipeline this is Layer 3 — anything here has passed deterministic rules
# and base model inference. For high-reputation packages, a missing git tag is a hard block.
HIGH_REP_BLOCK_THRESHOLD = 0.40


@app.route("/", methods=["GET", "POST"])
def dashboard():
    result = None
    error = None
    manifest_str = ""
    if request.method == "POST":
        manifest_str = request.form.get("manifest", "").strip()
        try:
            manifest = json.loads(manifest_str)
            from agent.gemini_classifier import classify
            from agent.enrichment import collect_signals
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

    # High-reputation path: MCP evidence takes precedence over Gemini
    if name in HIGH_REP:
        initial = classify(manifest)
        collected = collect_signals(manifest)
        override = collected["enrichment_confidence"] >= HIGH_REP_BLOCK_THRESHOLD
        # If MCP evidence isn't strong enough to block, default SAFE — Gemini is advisory only.
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

    # Standard path: Gemini score drives escalation
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
