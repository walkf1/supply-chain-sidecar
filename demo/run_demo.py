"""Supply Chain Sidecar — demo runner.

Two stages per scenario:
  Stage 1: collect_signals() in isolation — raw MCP evidence, no LLM
  Stage 2: full pipeline — Gemini + override logic

Run from repo root:
  PYTHONPATH=. python demo/run_demo.py
"""

import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"))

from agent.gemini_classifier import classify
from agent.enrichment import collect_signals
from agent.confidence import get_thresholds

SCENARIOS_PATH = os.path.join(os.path.dirname(__file__), "test_packages.json")
HIGH_REP = {"lodash", "axios", "chalk", "express", "react", "typescript", "webpack", "babel"}
HIGH_REP_BLOCK_THRESHOLD = 0.40  # must match assess.py
SIDECAR_MODE = os.getenv("SIDECAR_MODE", "balanced")

SEP = "─" * 72


def _final_verdict(name, gemini, collected, thresholds):
    if name in HIGH_REP:
        override = collected["enrichment_confidence"] >= HIGH_REP_BLOCK_THRESHOLD
        # MCP evidence drives the verdict for high-rep packages.
        # If override doesn't fire, MCP signals are insufficient — default SAFE.
        return "MALICIOUS" if override else "SAFE", override
    p = gemini["p_malicious"]
    if p >= thresholds["block"]:
        return "MALICIOUS", False
    return "SAFE", False


def run():
    with open(SCENARIOS_PATH) as f:
        scenarios = json.load(f)["scenarios"]

    thresholds = get_thresholds(SIDECAR_MODE)
    print(f"\n{'SUPPLY CHAIN SIDECAR — DEMO RUN':^72}")
    print(f"{'Mode: ' + SIDECAR_MODE + '  |  Block threshold: ' + str(thresholds['block']):^72}")

    results = []

    for s in scenarios:
        manifest = s["manifest"]
        name = manifest["name"]
        version = manifest["version"]
        expected = s["expected"]

        print(f"\n{SEP}")
        print(f"  {s['label']}")
        print(f"  {s['description']}")
        print(SEP)

        # Stage 1: MCP evidence only
        print("  [Stage 1] collect_signals() — registry evidence, no LLM")
        domain_age_override = s.get("domain_age_override")
        collected = collect_signals(manifest, _domain_age_override=domain_age_override)
        sig = collected["signals"]
        print(f"    git_tag_status  : {sig.get('git_tag_status', 'n/a')}")
        print(f"    git_tag_exists  : {sig.get('git_tag_exists', 'n/a')}")
        print(f"    publish_method  : {sig.get('publish_method', 'n/a')}")
        print(f"    domain          : {sig.get('domain', 'none')}")
        print(f"    domain_age_days : {sig.get('domain_age_days', 'n/a')}")
        print(f"    enrichment_conf : {collected['enrichment_confidence']:.3f}")
        print(f"    evidence        : {collected['evidence_summary']}")

        # Stage 2: Gemini classification
        print("  [Stage 2] Gemini classification")
        gemini = classify(manifest)
        print(f"    verdict         : {gemini['verdict']}")
        print(f"    p_malicious     : {gemini['p_malicious']:.3f}")
        if gemini["verdict"] == "UNKNOWN":
            print(f"    [!] Gemini error: {gemini.get('raw', 'no detail')}")

        # Final verdict
        final, overridden = _final_verdict(name, gemini, collected, thresholds)
        if overridden:
            print(f"  [Override] MCP evidence ({collected['enrichment_confidence']:.3f}) >= block threshold ({thresholds['block']}) → MALICIOUS")

        # Pass/fail
        if expected == "SAFE_FROM_GEMINI_MALICIOUS_FROM_MCP":
            passed = gemini["verdict"] == "SAFE" and final == "MALICIOUS"
            label = "SAFE→MALICIOUS (expected)"
        else:
            passed = final == expected
            label = expected

        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"  Result: {final:<12} Expected: {label:<30} {status}")
        results.append({"id": s["id"], "final": final, "gemini": gemini["verdict"],
                        "enrichment_conf": collected["enrichment_confidence"],
                        "expected": expected, "passed": passed})

    # Summary table
    print(f"\n{SEP}")
    print(f"  {'SCENARIO':<30} {'GEMINI':<12} {'MCP CONF':<10} {'FINAL':<12} {'STATUS'}")
    print(f"  {'─'*28:<30} {'─'*10:<12} {'─'*8:<10} {'─'*10:<12} {'─'*6}")
    for r in results:
        print(f"  {r['id']:<30} {r['gemini']:<12} {r['enrichment_conf']:<10.3f} {r['final']:<12} {'✓' if r['passed'] else '✗'}")

    passed_count = sum(1 for r in results if r["passed"])
    print(f"\n  {passed_count}/{len(results)} scenarios passed")
    print(SEP)

    return 0 if passed_count == len(results) else 1


if __name__ == "__main__":
    sys.exit(run())
