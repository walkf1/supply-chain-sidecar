"""Gemini package manifest classifier.

Sends package.json to Gemini via Vertex AI and returns a P(MALICIOUS) score.
Authenticates via application default credentials — no API key required.
"""

import os
import json
import re
from google import genai
from google.genai import types

PROJECT_ID = os.getenv("GCP_PROJECT", "carn-vm-testing")
LOCATION = os.getenv("GCP_LOCATION", "us-central1")
MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

SYSTEM_PROMPT = (
    "You are a supply chain security classifier. "
    "Analyze the provided npm package.json for signs of a manifest-only hijack attack. "
    "Focus on structural anomalies: missing git tags, newly registered domains in author "
    "or homepage fields, phantom dependencies in zero-dependency packages, postinstall "
    "scripts added to packages that have never had them. "
    "Respond with exactly two lines:\n"
    "VERDICT: SAFE\nSCORE: <float 0.0-1.0>\n"
    "or\n"
    "VERDICT: MALICIOUS\nSCORE: <float 0.0-1.0>\n"
    "where SCORE is your confidence that the package is malicious. "
    "Output nothing else."
)

_client = None


def _get_client() -> genai.Client:
    global _client
    if _client is None:
        _client = genai.Client(vertexai=True, project=PROJECT_ID, location=LOCATION)
    return _client


def classify(manifest: dict) -> dict:
    """Classify a package manifest. Returns verdict, p_malicious, raw response."""
    client = _get_client()
    prompt = f"Analyze this npm package.json for supply chain hijack indicators:\n\n{json.dumps(manifest, indent=2)[:2000]}\n\nIs this malicious?"
    try:
        response = client.models.generate_content(
            model=MODEL,
            contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                temperature=0.1,
                max_output_tokens=500,
            ),
        )
        return _parse(response.text.strip())
    except Exception as e:
        return {"verdict": "UNKNOWN", "p_malicious": 0.5, "raw": str(e)}


def _parse(raw: str) -> dict:
    verdict = "UNKNOWN"
    p_malicious = 0.5
    v = re.search(r"VERDICT:\s*(SAFE|MALICIOUS)", raw, re.IGNORECASE)
    s = re.search(r"SCORE:\s*([0-9.]+)", raw, re.IGNORECASE)
    if v:
        verdict = v.group(1).upper()
    if s:
        try:
            raw_score = float(s.group(1))
            # SCORE is confidence in the verdict — invert if SAFE
            p_malicious = raw_score if verdict == "MALICIOUS" else 1.0 - raw_score
        except ValueError:
            p_malicious = 1.0 if verdict == "MALICIOUS" else 0.0
    return {"verdict": verdict, "p_malicious": p_malicious, "raw": raw}
