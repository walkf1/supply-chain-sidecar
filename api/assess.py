"""Supply Chain Sidecar — /assess API."""

import os
from flask import Flask, request, jsonify
from agent.gemini_classifier import classify
from agent.enrichment import enrich
from agent.confidence import get_thresholds

app = Flask(__name__)
SIDECAR_MODE = os.getenv("SIDECAR_MODE", "balanced")


@app.route("/assess", methods=["POST"])
def assess():
    data = request.get_json(force=True)
    manifest = data.get("manifest") or {}
    if not manifest:
        manifest = {"name": data.get("name", "unknown"), "version": data.get("version", "unknown")}

    initial = classify(manifest)
    p_mal = initial["p_malicious"]
    thresholds = get_thresholds(SIDECAR_MODE)

    if p_mal >= thresholds["block"]:
        return jsonify({"verdict": "MALICIOUS", "confidence": p_mal, "enriched": False, "evidence_summary": initial["raw"]})

    if p_mal < thresholds["escalate"]:
        return jsonify({"verdict": "SAFE", "confidence": 1.0 - p_mal, "enriched": False, "evidence_summary": "Below escalation threshold."})

    result = enrich(manifest, initial)
    result["verdict"] = "MALICIOUS" if result["confidence"] >= thresholds["block"] else "SAFE"
    return jsonify(result)


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "mode": SIDECAR_MODE})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 8080)))
