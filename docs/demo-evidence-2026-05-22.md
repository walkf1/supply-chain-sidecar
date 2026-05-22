# Demo Evidence — Supply Chain Sidecar

**Date:** 2026-05-22T06:35:44Z  
**Model:** gemini-2.5-flash (Vertex AI, us-central1)  
**Project:** supply-chain-sidecar (GCP)  
**Mode:** balanced | Block threshold: 0.7 | HIGH_REP_BLOCK_THRESHOLD: 0.40  
**Result:** 4/4 scenarios passed ✓

---

## What This Demonstrates

The Halo Effect is real. A model that recognises a high-reputation package name trusts it,
even when registry metadata signals an attack. Supply Chain Sidecar catches what Gemini misses
by fetching live evidence via Elastic MCP and injecting it as structured facts.

The `lodash_attack` scenario is the proof: Gemini returns SAFE. MCP returns no git tag.
Final verdict: MALICIOUS. The attack is caught entirely from registry metadata — no manifest
content signal required.

---

## Scenario Results

### axios@1.14.0 — clean release ✓ PASS

```
[Stage 1] collect_signals() — registry evidence, no LLM
  git_tag_status  : before_publish
  git_tag_exists  : True
  publish_method  : manual_token
  domain          : None
  domain_age_days : None
  enrichment_conf : 0.200
  evidence        : Published via manual_token (not ci-cd).

[Stage 2] Gemini classification
  verdict         : SAFE
  p_malicious     : 0.950

Result: SAFE    Expected: SAFE    ✓ PASS
```

### axios@1.14.1 — manifest-only hijack ✓ PASS

```
[Stage 1] collect_signals() — registry evidence, no LLM
  git_tag_status  : missing
  git_tag_exists  : False
  publish_method  : unknown
  domain          : None
  domain_age_days : None
  enrichment_conf : 0.600
  evidence        : Published via unknown (not ci-cd). no git tag for this version.

[Stage 2] Gemini classification
  verdict         : MALICIOUS
  p_malicious     : 0.950

[Override] MCP evidence (0.600) >= HIGH_REP_BLOCK_THRESHOLD (0.40) → MALICIOUS
Result: MALICIOUS    Expected: MALICIOUS    ✓ PASS
```

Both Gemini and MCP agree. Phantom dependency `plain-crypto-js` caught by Gemini.
MCP confirms no git tag — double signal.

### lodash@4.17.21 — clean release ✓ PASS

```
[Stage 1] collect_signals() — registry evidence, no LLM
  git_tag_status  : before_publish
  git_tag_exists  : True
  publish_method  : manual_token
  domain          : None
  domain_age_days : None
  enrichment_conf : 0.200
  evidence        : Published via manual_token (not ci-cd).

[Stage 2] Gemini classification
  verdict         : SAFE
  p_malicious     : 0.950

Result: SAFE    Expected: SAFE    ✓ PASS
```

### lodash@4.17.22 — version-jump hijack ✓ PASS  ← KEY SCENARIO

```
[Stage 1] collect_signals() — registry evidence, no LLM
  git_tag_status  : missing
  git_tag_exists  : False
  publish_method  : unknown
  domain          : None
  domain_age_days : None
  enrichment_conf : 0.600
  evidence        : Published via unknown (not ci-cd). no git tag for this version.

[Stage 2] Gemini classification
  verdict         : SAFE       ← Halo Effect — manifest looks clean
  p_malicious     : 0.050

[Override] MCP evidence (0.600) >= HIGH_REP_BLOCK_THRESHOLD (0.40) → MALICIOUS
Result: MALICIOUS    Expected: SAFE→MALICIOUS    ✓ PASS
```

**This is the core thesis.** Gemini sees a clean lodash manifest and says SAFE.
MCP fetches live registry metadata: no git tag for v4.17.22, published via unknown method.
Enrichment confidence: 0.600 — above the high-rep block threshold.
Final verdict: MALICIOUS. Attack caught entirely from registry metadata.

---

## Summary Table

| SCENARIO      | GEMINI   | MCP CONF | FINAL    | STATUS |
|---------------|----------|----------|----------|--------|
| axios_clean   | SAFE     | 0.200    | SAFE     | ✓      |
| axios_attack  | MALICIOUS| 0.600    | MALICIOUS| ✓      |
| lodash_clean  | SAFE     | 0.200    | SAFE     | ✓      |
| lodash_attack | SAFE     | 0.600    | MALICIOUS| ✓      |

---

## Confidence Scoring (confidence.py)

| Signal         | Condition      | Weight |
|----------------|----------------|--------|
| git_tag        | missing        | +0.40  |
| git_tag        | after_publish  | +0.20  |
| git_tag        | before_publish | +0.00  |
| publish_method | manual_token   | +0.20  |
| publish_method | unknown        | +0.20  |
| publish_method | oidc / ci_cd   | +0.00  |
| domain_age     | < 30 days      | +0.70  |
| domain_age     | 30–90 days     | +0.30  |
| domain_age     | > 90 days      | +0.00  |

Clean package (git tag exists, manual token): 0.20 → below threshold → SAFE  
Attack package (no git tag, unknown method): 0.60 → above HIGH_REP threshold → MALICIOUS

---

## Stack

- Gemini 2.5 Flash — Vertex AI (us-central1)
- Elastic MCP Server — three tools: get_git_tag, get_domain_age, get_publish_method
- Elastic Cloud — signal caching and audit trail
- Flask — /assess API
- npm registry (live) — real package metadata fetched at intercept time
