# Supply Chain Sidecar

**Google Cloud Rapid Agent Hackathon — Elastic Track**

The Halo Effect is real. AI-based security tools that recognise a high-reputation package
name — lodash, axios, chalk — trust it, even when the manifest contains a structural
anomaly that signals an attack. The attack is invisible to the model because the signal
is not in the package content. It is in the registry metadata.

Supply Chain Sidecar catches what AI classifiers miss by fetching live registry evidence
at intercept time and injecting it as structured facts into the verdict.

---

## The Problem

Most supply chain security tools detect known vulnerabilities by matching against a
database of known malware. That approach fails against a class of attack that has become
increasingly common: the manifest-only hijack.

In a manifest-only hijack, the attacker publishes a version of a legitimate, high-reputation
package with a single structural mutation — a phantom dependency, a missing git tag, an
author domain registered days before publish. The package content looks legitimate. A model
operating on package.json alone cannot distinguish it from a real release.

The real-world example is the Axios 1.14.1 attack (March 2026). The maintainer account
was compromised. A single phantom dependency — `plain-crypto-js` — was injected. The
package was live on npm for hours before removal. A postinstall hook deployed a
cross-platform RAT. The only reliable signal was in the registry metadata: no git tag
for that version, the attacker domain registered shortly before publish.

Supply Chain Sidecar is built to catch exactly this class of attack.

---

## How It Works

```
npm install <package>
        |
        v
Proxy intercepts tarball request
        |
        v
Gemini 2.5 Flash assesses package.json  -->  P(MALICIOUS) score
        |
        +-- below allow threshold  -->  ALLOWED
        |
        +-- above block threshold  -->  BLOCKED
        |
        +-- high-reputation package  -->  Elastic MCP always runs
        |
        +-- borderline range  -->  Elastic MCP activates
                |
                v
        Tool 1: get_git_tag(name, version)
        Tool 2: get_domain_age(domain)
        Tool 3: get_publish_method(name, version)
                |
                v
        Enrichment confidence score assembled from weighted signals
                |
                v
        If MCP evidence exceeds threshold: override to MALICIOUS
        If MCP evidence is clean: confirm Gemini verdict
                |
                v
        Final verdict + evidence trail -> Dashboard
```

**Key design decision:** For high-reputation packages, MCP enrichment always runs —
regardless of Gemini's verdict. Manifest-only hijack attacks target precisely these
packages, and their package content is indistinguishable from a legitimate release
without registry metadata. Gemini's verdict is used as a signal, not as the final word.

---

## The Demo

The lodash@4.17.22 scenario demonstrates the core thesis:

```
lodash@4.17.21  -->  Gemini: SAFE
                     MCP: git tag confirmed, manual token (consistent with prior releases)
                     Enrichment confidence: 0.20
                     Final verdict: SAFE

lodash@4.17.22  -->  Gemini: SAFE  (manifest content is identical — Halo Effect)
                     MCP: no git tag for this version, published via unknown method
                     Enrichment confidence: 0.60
                     MCP evidence exceeds high-rep threshold (0.40)
                     Final verdict: MALICIOUS
```

Gemini sees a clean lodash manifest and says SAFE. MCP fetches live registry metadata,
finds no git tag for v4.17.22, and overrides the verdict. The attack is caught entirely
from registry signals — no manifest content change required.

Validated results across all four demo scenarios (2026-05-22):

| Scenario          | Gemini  | MCP Confidence | Final     |
|-------------------|---------|----------------|-----------|
| axios@1.14.0      | SAFE    | 0.20           | SAFE      |
| axios@1.14.1      | MALICIOUS | 0.60         | MALICIOUS |
| lodash@4.17.21    | SAFE    | 0.20           | SAFE      |
| lodash@4.17.22    | SAFE    | 0.60           | MALICIOUS |

---

## Why Elastic

The sidecar needs a live, queryable index of package reputation signals — git tag
verification results, domain registration records, publish method history — that can be
queried at intercept time without adding meaningful latency.

Elastic is the right fit for three reasons:

1. **Sub-millisecond cache reads.** Registry signals fetched on first encounter are
   indexed in Elastic and returned from cache on subsequent requests. The live npm
   registry and RDAP calls happen once per package version, not on every install.

2. **Structured metadata queries.** Each signal is a structured document — package name,
   version, domain, age in days, publish method, git head hash. Elastic's document model
   maps directly to this schema.

3. **Sovereign deployment path.** In an air-gapped enterprise deployment, the same Elastic
   index runs on-premises, pointing at a local npm registry mirror and a local WHOIS cache.
   No architecture change required — only the endpoint configuration changes.

The MCP server exposes the three tools directly. The agent calls them as part of the
assessment pipeline, not as a post-hoc lookup.

---

## Confidence Scoring

Each registry signal contributes a weighted score to an aggregate enrichment confidence.
The confidence score determines whether the MCP evidence overrides the Gemini verdict.

| Signal         | Condition          | Contribution |
|----------------|--------------------|--------------|
| Domain age     | < 30 days          | +0.70        |
| Domain age     | 30-90 days         | +0.30        |
| Domain age     | > 90 days          | +0.00        |
| Publish method | Manual token       | +0.20        |
| Publish method | Unknown            | +0.20        |
| Publish method | OIDC / CI-CD       | +0.00        |
| Git tag        | Missing            | +0.40        |
| Git tag        | Created after publish | +0.20     |
| Git tag        | Created before publish | +0.00    |

A clean package with a confirmed git tag and manual token publish scores 0.20 — below
the high-reputation block threshold of 0.40. An attack package with no git tag and
unknown publish method scores 0.60 — above threshold, verdict overridden to MALICIOUS.

---

## CISO Risk Tolerance

Set via the `SIDECAR_MODE` environment variable:

| Mode       | Block threshold | Escalate threshold | Profile                        |
|------------|-----------------|--------------------|--------------------------------|
| strict     | 0.5             | 0.3                | Regulated environments, CNI    |
| balanced   | 0.7             | 0.5                | Default enterprise             |
| permissive | 0.9             | 0.7                | High-velocity development teams |

The block and escalate thresholds control when Gemini's verdict is accepted outright
versus when MCP enrichment activates. High-reputation packages use a separate, lower
threshold (`HIGH_REP_BLOCK_THRESHOLD = 0.40`) regardless of mode.

---

## Live Demo

Dashboard: https://supply-chain-sidecar-379478531186.us-central1.run.app

API: https://supply-chain-sidecar-379478531186.us-central1.run.app/assess

Load a scenario from the dashboard buttons, or POST directly to `/assess`:

```bash
curl -X POST https://supply-chain-sidecar-379478531186.us-central1.run.app/assess \
  -H "Content-Type: application/json" \
  -d '{
    "manifest": {
      "name": "lodash",
      "version": "4.17.22",
      "description": "Lodash modular utilities.",
      "scripts": {"test": "echo test"},
      "dependencies": {},
      "maintainers": [{"name": "jdalton"}],
      "license": "MIT"
    }
  }'
```

---

## Setup

```bash
git clone https://github.com/walkf1/supply-chain-sidecar.git
cd supply-chain-sidecar
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Add ELASTIC_CLOUD_ID, ELASTIC_API_KEY, and GCP credentials to .env
```

Start the sidecar:

```bash
python3 api/assess.py
```

Start the proxy stub (optional — intercepts npm installs):

```bash
python3 proxy_stub.py
npm config set registry http://localhost:4873
npm install lodash
```

Run the demo scenarios:

```bash
python3 demo/run_demo.py
```

---

## Project Structure

```
supply-chain-sidecar/
├── proxy_stub.py              # Minimal npm proxy — intercepts, calls /assess
├── agent/
│   ├── gemini_classifier.py   # Gemini 2.5 Flash via Vertex AI
│   ├── enrichment.py          # MCP signal collection and Gemini re-ranking
│   └── confidence.py          # Signal weighting and score assembly
├── mcp/
│   └── elastic_mcp_server.py  # Three MCP tools — git tag, domain age, publish method
├── api/
│   └── assess.py              # /assess endpoint and evidence trail dashboard
├── demo/
│   ├── test_packages.json     # Five scenarios including real Axios March 2026 attack
│   └── run_demo.py            # One-command demo runner
└── docs/
    └── demo-evidence-2026-05-22.md  # Validated run output with full signal traces
```

---

## A Note on Domain Age Scenarios

The domain age signal (lodash@4.17.23 scenario) uses a synthetic domain age injected
directly into the enrichment pipeline. This is the correct approach for a demo: real
attacker domains from the Axios March 2026 attack (sfrclak.com) cannot be re-deployed,
and registering a new attacker domain for a demo would be inappropriate.

The synthetic injection simulates what the Elastic cache would return in production for
a real attacker domain registered 3 days before publish — the exact pattern observed in
the Axios incident. The enrichment pipeline, confidence scoring, and override logic are
identical whether the domain age comes from a live RDAP lookup, an Elastic cache hit,
or a synthetic injection. The signal path is what is being demonstrated.

---

## Stack

- Gemini 2.5 Flash — Vertex AI (us-central1)
- Elastic Cloud — signal caching and audit trail
- Google Cloud Run — deployment
- Flask — /assess API and dashboard
- npm registry (live) — real package metadata fetched at intercept time
- RDAP — domain registration lookups

---

## Licence

MIT — see LICENSE file.
