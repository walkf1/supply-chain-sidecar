# Supply Chain Sidecar

**Google Cloud Rapid Agent Hackathon — Elastic Track**

The 'Halo Effect' is real...and your security layer needs a sidecar. Supply Chain Sidecar
catches unknown malware and hijack attacks in otherwise legitimate packages.

Most supply chain security tools detect known vulnerabilities by relying on a database of
known malware. Supply Chain Sidecar catches the unknown: manifest-only hijack attacks in
an otherwise legitimate package.

---

## The Problem

AI-based security tools suffer from the Halo Effect — a model that recognises a
high-reputation package name (lodash, axios, chalk) trusts it, even when the manifest
contains a structural anomaly: a missing git tag, a newly registered author domain, a
phantom dependency. The attack is invisible to the model because the signal is not in the
package content. It is in the registry metadata.

Supply Chain Sidecar solves this by fetching live registry evidence at intercept time and
injecting it into the AI verdict as structured facts.

---

## How It Works

```
npm install <package>
        |
        v
Proxy intercepts tarball
        |
        v
Gemini assesses package.json  -->  P(MAL) score
        |
        +-- below allow threshold  -->  ALLOWED
        |
        +-- above block threshold  -->  BLOCKED
        |
        +-- borderline range  -->  Elastic MCP activates
                |
                v
        Tool 1: get_git_tag(name, version)
        Tool 2: get_domain_age(domain)
        Tool 3: get_publish_method(name, version)
                |
                v
        Confidence score assembled
                |
                v
        Gemini re-inference with enriched prompt
                |
                v
        Final verdict + evidence trail
```

---

## Confidence Scoring

| Signal | Condition | Contribution |
|---|---|---|
| Domain age | < 30 days | +0.70 |
| Domain age | 30-90 days | +0.30 |
| Domain age | > 90 days | +0.00 |
| Publish method | Manual token | +0.50 |
| Publish method | OIDC / CI-CD | +0.00 |
| Git tag | No tag exists | +0.40 |
| Git tag | Tag after publish | +0.20 |
| Git tag | Tag before publish | +0.00 |

---

## CISO Risk Tolerance

Set via `SIDECAR_MODE` environment variable:

| Mode | Block threshold | Escalate threshold | Profile |
|---|---|---|---|
| strict | 0.5 | 0.3 | Regulated environments, CNI |
| balanced | 0.7 | 0.5 | Default enterprise |
| permissive | 0.9 | 0.7 | High-velocity dev teams |

---

## Setup

```bash
git clone https://github.com/walkf1/supply-chain-sidecar.git
cd supply-chain-sidecar
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Add your ELASTIC_CLOUD_ID, ELASTIC_API_KEY and GCP credentials to .env
```

Start the sidecar:

```bash
python3 api/assess.py
```

Start the proxy:

```bash
python3 proxy_stub.py
npm config set registry http://localhost:4873
npm install lodash
```

---

## The /assess API

```
POST /assess
{
  "name": "lodash",
  "version": "4.17.22",
  "manifest": { ...package.json... }
}
```

---

## Project Structure

```
supply-chain-sidecar/
├── proxy_stub.py              # npm proxy
├── agent/
│   ├── gemini_classifier.py   # Gemini assessment
│   ├── enrichment.py          # MCP enrichment orchestrator
│   └── confidence.py          # Signal weighting
├── mcp/
│   └── elastic_mcp_server.py  # Elastic MCP — three tools
├── api/
│   └── assess.py              # /assess endpoint
└── demo/
    └── test_packages.json     # Attack scenarios
```

---

## Built With

- Gemini 2.0 Flash via Vertex AI
- Google Cloud Agent Builder
- Elastic MCP Server
- Cloud Run

---

## Licence

MIT — see LICENSE file.
