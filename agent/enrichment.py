"""Enrichment orchestrator — triggers MCP when Gemini verdict is borderline."""

import os
import re
from agent.confidence import score, build_enriched_prompt
from agent.gemini_classifier import _get_client, MODEL
from mcp.elastic_mcp_server import get_git_tag, get_domain_age, get_publish_method
from google.genai import types

SYSTEM_PROMPT = (
    "You are a supply chain security classifier. "
    "Analyze the provided npm package.json and the additional registry evidence. "
    "Respond with exactly two lines:\n"
    "VERDICT: SAFE\nSCORE: <float 0.0-1.0>\n"
    "or\n"
    "VERDICT: MALICIOUS\nSCORE: <float 0.0-1.0>\n"
    "Output nothing else."
)


def enrich(manifest: dict, initial_result: dict) -> dict:
    name = manifest.get("name", "unknown")
    version = manifest.get("version", "unknown")
    domain = _extract_domain(manifest)

    git_result = get_git_tag(name, version)
    domain_result = get_domain_age(domain) if domain else {"age_days": None, "domain": None}
    method_result = get_publish_method(name, version)

    signals = {
        "domain": domain,
        "domain_age_days": domain_result.get("age_days"),
        "publish_method": method_result.get("method"),
        "git_tag_status": git_result.get("status"),
        "git_tag_exists": git_result.get("exists"),
    }

    scored = score(signals)
    enriched_prompt = build_enriched_prompt(manifest, signals, scored)

    try:
        client = _get_client()
        response = client.models.generate_content(
            model=MODEL,
            contents=enriched_prompt,
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                temperature=0.1,
                max_output_tokens=60,
            ),
        )
        final = _parse(response.text.strip())
    except Exception as e:
        final = {"verdict": initial_result["verdict"], "p_malicious": initial_result["p_malicious"], "raw": str(e)}

    return {
        "verdict": final["verdict"],
        "confidence": final["p_malicious"],
        "enriched": True,
        "signals": signals,
        "enrichment_confidence": scored["enrichment_confidence"],
        "evidence_summary": scored["evidence_summary"],
        "raw_response": final["raw"],
    }


def _extract_domain(manifest: dict) -> str | None:
    for field in ["homepage", "bugs"]:
        val = manifest.get(field)
        if isinstance(val, str) and val.startswith("http"):
            return val.replace("https://", "").replace("http://", "").split("/")[0]
        if isinstance(val, dict):
            url = val.get("url", "")
            if url.startswith("http"):
                return url.replace("https://", "").replace("http://", "").split("/")[0]
    author = manifest.get("author")
    if isinstance(author, dict):
        url = author.get("url", "")
        if url.startswith("http"):
            return url.replace("https://", "").replace("http://", "").split("/")[0]
    if isinstance(author, str) and "http" in author:
        match = re.search(r'https?://([^/\s)]+)', author)
        if match:
            return match.group(1)
    return None


def _parse(raw: str) -> dict:
    verdict, p_malicious = "UNKNOWN", 0.5
    v = re.search(r"VERDICT:\s*(SAFE|MALICIOUS)", raw, re.IGNORECASE)
    s = re.search(r"SCORE:\s*([0-9.]+)", raw, re.IGNORECASE)
    if v:
        verdict = v.group(1).upper()
    if s:
        try:
            p_malicious = float(s.group(1))
        except ValueError:
            p_malicious = 1.0 if verdict == "MALICIOUS" else 0.0
    return {"verdict": verdict, "p_malicious": p_malicious, "raw": raw}
