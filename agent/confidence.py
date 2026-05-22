"""Confidence scoring for MCP enrichment signals."""

import json

THRESHOLDS = {
    "strict":     {"block": 0.5, "escalate": 0.3},
    "balanced":   {"block": 0.7, "escalate": 0.5},
    "permissive": {"block": 0.9, "escalate": 0.7},
}

WEIGHTS = {
    "domain_age":     [(30, 0.70), (90, 0.30), (None, 0.00)],
    "publish_method": {"manual_token": 0.20, "oidc": 0.00, "ci_cd": 0.00, "unknown": 0.20},
    "git_tag":        {"missing": 0.40, "after_publish": 0.20, "before_publish": 0.00, "unknown": 0.10},
}


def score(signals: dict) -> dict:
    contributions = {}
    evidence_parts = []

    domain_age = signals.get("domain_age_days")
    if domain_age is not None:
        for threshold, weight in WEIGHTS["domain_age"]:
            if threshold is None or domain_age < threshold:
                contributions["domain_age"] = weight
                if weight > 0:
                    evidence_parts.append(f"{signals.get('domain', 'unknown domain')} registered {domain_age} days before publish")
                break

    method = (signals.get("publish_method") or "unknown").lower().replace("-", "_")
    method_key = method if method in WEIGHTS["publish_method"] else "unknown"
    contributions["publish_method"] = WEIGHTS["publish_method"][method_key]
    if contributions["publish_method"] > 0:
        evidence_parts.append(f"published via {method} (not CI-CD)")

    tag_status = (signals.get("git_tag_status") or "unknown").lower()
    tag_key = tag_status if tag_status in WEIGHTS["git_tag"] else "unknown"
    contributions["git_tag"] = WEIGHTS["git_tag"][tag_key]
    if tag_status == "missing":
        evidence_parts.append("no git tag for this version")
    elif tag_status == "after_publish":
        evidence_parts.append("git tag created after publish")

    total = min(sum(contributions.values()), 1.0)
    evidence_summary = ". ".join(evidence_parts).capitalize() + "." if evidence_parts else "No anomalies detected."

    return {
        "enrichment_confidence": round(total, 3),
        "contributions": contributions,
        "evidence_summary": evidence_summary,
    }


def get_thresholds(mode: str = "balanced") -> dict:
    return THRESHOLDS.get(mode, THRESHOLDS["balanced"])


def build_enriched_prompt(manifest: dict, signals: dict, scored: dict) -> str:
    return (
        f"Analyze this npm package.json for supply chain hijack indicators:\n\n"
        f"{json.dumps(manifest, indent=2)[:1500]}\n\n"
        f"Additional registry evidence:\n"
        f"- {scored['evidence_summary']}\n"
        f"- Enrichment confidence score: {scored['enrichment_confidence']:.2f}\n\n"
        f"Given this evidence, is this package malicious?"
    )
