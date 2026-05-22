"""Enrichment pipeline — MCP signal collection and Gemini re-ranking.

Two distinct stages:
  collect_signals() — fetches registry evidence via MCP, scores it
  rerank()          — re-asks Gemini with evidence in context
  enrich()          — orchestrates both (used by borderline path)
"""

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


def collect_signals(manifest: dict, _domain_age_override: int | None = None) -> dict:
    """Fetch MCP registry signals and score them. No Gemini call.

    _domain_age_override: inject a domain age (days) directly — used in demo scenarios
    where the attacker domain is fictional and RDAP returns nothing.
    """
    name = manifest.get("name", "unknown")
    version = manifest.get("version", "unknown")
    domain = _extract_domain(manifest)

    git_result = get_git_tag(name, version)
    if _domain_age_override is not None and domain:
        domain_result = {"age_days": _domain_age_override, "domain": domain}
    else:
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
    return {
        "signals": signals,
        "enrichment_confidence": scored["enrichment_confidence"],
        "contributions": scored["contributions"],
        "evidence_summary": scored["evidence_summary"],
    }


def rerank(manifest: dict, collected: dict, initial_result: dict) -> dict:
    """Re-ask Gemini with MCP evidence in context. Returns updated verdict."""
    scored = {
        "enrichment_confidence": collected["enrichment_confidence"],
        "evidence_summary": collected["evidence_summary"],
    }
    enriched_prompt = build_enriched_prompt(manifest, collected["signals"], scored)

    try:
        client = _get_client()
        response = client.models.generate_content(
            model=MODEL,
            contents=enriched_prompt,
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                temperature=0.1,
                max_output_tokens=60,
                timeout=15,
            ),
        )
        final = _parse(response.text.strip())
    except Exception as e:
        final = {"verdict": initial_result["verdict"], "p_malicious": initial_result["p_malicious"], "raw": str(e)}

    return {
        "verdict": final["verdict"],
        "confidence": final["p_malicious"],
        "raw_response": final["raw"],
    }


def enrich(manifest: dict, initial_result: dict) -> dict:
    """Full enrichment: collect signals then rerank with Gemini. Used for borderline path."""
    collected = collect_signals(manifest)
    reranked = rerank(manifest, collected, initial_result)

    return {
        "verdict": reranked["verdict"],
        "confidence": reranked["confidence"],
        "enriched": True,
        "signals": collected["signals"],
        "enrichment_confidence": collected["enrichment_confidence"],
        "evidence_summary": collected["evidence_summary"],
        "raw_response": reranked["raw_response"],
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
