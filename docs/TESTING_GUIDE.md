# Testing Guide

## The fastest path — no setup required

The sidecar is live on Cloud Run. Open the dashboard in a browser:

```
https://supply-chain-sidecar-379478531186.us-central1.run.app
```

Everything below can be done from this URL. No credentials, no local install.

---

## Dashboard walkthrough

The dashboard has four scenario buttons across the top. Work through them in order —
they tell a story.

### 1. axios@1.14.0 — clean release

Click the button. Hit Assess.

What to expect:
- Verdict: SAFE
- MCP enrichment confidence: 20%
- Git tag: confirmed (before_publish)
- Evidence: published via manual token — consistent with all prior axios releases

This is the baseline. A legitimate package. MCP confirms it.

### 2. axios@1.14.1 — attack

Click the button. Hit Assess.

What to expect:
- Verdict: MALICIOUS
- MCP enrichment confidence: 60%
- Git tag: missing
- Evidence: phantom dependency `plain-crypto-js` injected, no git tag

This is the real March 2026 attack. Gemini catches the phantom dependency in the
manifest. MCP confirms no git tag. Both signals agree.

### 3. lodash@4.17.21 — clean release

Click the button. Hit Assess.

What to expect:
- Verdict: SAFE
- MCP enrichment confidence: 20%
- Git tag: confirmed

Clean lodash. MCP confirms it. This sets up the next scenario.

### 4. lodash@4.17.22 — hijack

Click the button. Hit Assess.

What to expect:
- Verdict: MALICIOUS
- Gemini verdict (shown separately): SAFE
- MCP enrichment confidence: 60%
- Override badge: MCP Override
- Evidence: no git tag for this version, published via unknown method

This is the key scenario. The manifest is identical to 4.17.21 — Gemini sees nothing
wrong and says SAFE. MCP fetches live registry metadata, finds no git tag for this
version, and overrides the verdict to MALICIOUS. The attack is caught entirely from
registry signals.

---

## API — test directly with curl

The `/assess` endpoint accepts any package manifest as JSON.

Clean package:

```bash
curl -s -X POST \
  https://supply-chain-sidecar-379478531186.us-central1.run.app/assess \
  -H "Content-Type: application/json" \
  -d '{"manifest": {"name": "lodash", "version": "4.17.21", "description": "Lodash modular utilities.", "scripts": {"test": "echo test"}, "dependencies": {}, "maintainers": [{"name": "jdalton"}], "license": "MIT"}}' \
  | python3 -m json.tool
```

Attack package (same manifest, version bump, no git tag in registry):

```bash
curl -s -X POST \
  https://supply-chain-sidecar-379478531186.us-central1.run.app/assess \
  -H "Content-Type: application/json" \
  -d '{"manifest": {"name": "lodash", "version": "4.17.22", "description": "Lodash modular utilities.", "scripts": {"test": "echo test"}, "dependencies": {}, "maintainers": [{"name": "jdalton"}], "license": "MIT"}}' \
  | python3 -m json.tool
```

Health check:

```bash
curl https://supply-chain-sidecar-379478531186.us-central1.run.app/health
```

Expected response shape from `/assess`:

```json
{
  "verdict": "MALICIOUS",
  "confidence": 0.6,
  "enriched": true,
  "signals": {
    "domain": null,
    "domain_age_days": null,
    "publish_method": "unknown",
    "git_tag_status": "missing",
    "git_tag_exists": false
  },
  "enrichment_confidence": 0.6,
  "evidence_summary": "Published via unknown (not ci-cd). No git tag for this version.",
  "override_reason": "high-reputation package — MCP evidence takes precedence",
  "gemini_verdict": "SAFE"
}
```

---

## What to look for in the response

- `gemini_verdict` vs `verdict` — when these differ, MCP has overridden Gemini
- `override_reason` — present only when MCP evidence drove the final verdict
- `enrichment_confidence` — the weighted score from registry signals (0.0–1.0)
- `signals` — the raw values fetched from npm registry and RDAP
- `evidence_summary` — plain English summary of what MCP found

---

## Local setup — if you want to run it yourself

Requirements: Python 3.10+, a GCP project with Vertex AI enabled, an Elastic Cloud account.

```bash
git clone https://github.com/walkf1/supply-chain-sidecar.git
cd supply-chain-sidecar
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env — add your ELASTIC_CLOUD_ID, ELASTIC_API_KEY, GCP_PROJECT
```

Start the sidecar:

```bash
PYTHONPATH=. python3 api/assess.py
```

Run the demo scenarios against your local instance:

```bash
PYTHONPATH=. python3 demo/run_demo.py
```

Expected output: 4/5 scenarios pass (the domain age scenario uses a synthetic injection
and requires the `domain_age_override` field in the scenario — see `demo/test_packages.json`).

### Optional — npm proxy

To intercept real npm installs:

```bash
PYTHONPATH=. python3 proxy_stub.py
npm config set registry http://localhost:4873
npm install lodash
# Revert when done
npm config delete registry
```

The proxy intercepts the tarball request, extracts `package.json`, calls `/assess`,
and either forwards the tarball or returns 403.

---

## Known behaviour

- First call to a package version hits the live npm registry and RDAP — takes 1–3 seconds
- Subsequent calls for the same version are served from the Elastic cache — under 500ms
- If Elastic is unreachable, the sidecar falls back to Gemini verdict only (no MCP enrichment)
- If Gemini is unreachable, verdict returns UNKNOWN with confidence 0.5
