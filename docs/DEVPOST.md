# Devpost Submission — Supply Chain Sidecar

## Inspiration

In March 2026, the axios npm package was compromised. The maintainer account was hijacked,
a single phantom dependency was injected, and a cross-platform RAT was deployed to every
developer who ran `npm install axios` during the window it was live.

The attack was caught by Aikido Security — but only after the fact. The package had already
been downloaded thousands of times.

What struck us about this attack was not the sophistication of the payload. It was the
simplicity of the signal. The attacker domain was registered three days before publish.
There was no git tag for the new version. The package was published via an unknown method
rather than the CI/CD pipeline that had published every prior release.

None of that information is in the package.json. An AI classifier operating on manifest
content alone cannot see it. The signal is entirely in the registry metadata.

That is the problem Supply Chain Sidecar is built to solve.

---

## What It Does

Supply Chain Sidecar is an agent that intercepts npm package installs and catches a class
of attack that AI classifiers cannot detect from package content alone: the manifest-only
hijack.

When a developer runs `npm install`, the sidecar proxy intercepts the request before the
tarball reaches the machine. It runs two assessments in parallel:

**Gemini 2.5 Flash** assesses the package.json for structural anomalies — phantom
dependencies, suspicious postinstall scripts, obfuscated execution patterns.

**Elastic MCP** fetches live registry evidence for high-reputation packages — git tag
verification, domain registration age, publish method (OIDC CI/CD vs manual token).

For packages like lodash, axios, and chalk, MCP enrichment always runs regardless of
Gemini's verdict. These are precisely the packages that manifest-only hijack attacks
target, and their package content is indistinguishable from a legitimate release without
registry metadata.

If MCP evidence exceeds the confidence threshold, it overrides the Gemini verdict. The
final decision and the full evidence trail are returned to the dashboard.

The demo shows this working on the real axios@1.14.1 attack and a modelled lodash
version-jump hijack. In the lodash scenario, Gemini returns SAFE — the manifest is
identical to a legitimate release. MCP finds no git tag for that version and overrides
the verdict to MALICIOUS.

---

## How We Built It

**Agent architecture**

The pipeline has two stages. Stage 1 runs without any LLM call — it fetches registry
signals via the three Elastic MCP tools and assembles a weighted confidence score.
Stage 2 runs Gemini classification on the manifest. For high-reputation packages, the
MCP confidence score drives the final verdict directly. For borderline cases on unknown
packages, the enriched prompt (manifest + MCP evidence as structured facts) is passed
to Gemini for re-inference.

**Elastic MCP server**

Three tools expose the registry evidence layer:

- `get_git_tag(name, version)` — checks the npm registry for a gitHead field on the
  version record. Absence of a git tag on a high-reputation package is a strong signal.
- `get_domain_age(domain)` — queries RDAP for the registration date of the author or
  homepage domain. A domain registered days before publish is the pattern from the real
  Axios attack.
- `get_publish_method(name, version)` — checks whether the package was published via
  OIDC provenance (CI/CD) or a manual token. Manual token publish on a package that has
  historically used CI/CD is an anomaly.

Each tool checks the Elastic index for a cached result first. On cache miss it fetches
live and indexes the result. This means the first call to a package version hits the
live registry; subsequent calls are served from Elastic in under 500ms.

**Confidence scoring**

Each signal contributes a weighted score to an aggregate enrichment confidence. The
weights reflect the empirical signal strength of each indicator:

| Signal | Condition | Weight |
|---|---|---|
| Domain age | < 30 days | +0.70 |
| Domain age | 30-90 days | +0.30 |
| Publish method | Manual token / unknown | +0.20 |
| Git tag | Missing | +0.40 |
| Git tag | Created after publish | +0.20 |

A clean package (git tag confirmed, manual token consistent with prior releases) scores
0.20 — below the high-reputation block threshold of 0.40. An attack package (no git tag,
unknown publish method) scores 0.60 — above threshold, verdict overridden to MALICIOUS.

**Infrastructure**

- Gemini 2.5 Flash via Vertex AI (us-central1)
- Elastic Cloud — signal caching and audit trail
- Google Cloud Run — containerised deployment
- Flask — /assess API and evidence trail dashboard

---

## Challenges

**The signal visibility boundary**

The core challenge was not building the pipeline — it was understanding precisely where
AI classification fails and why. A model operating on package.json alone cannot detect
a manifest-only hijack because the attack signal is not encoded in the package content.
It is a structural anomaly in the relationship between the package and its registry
history. Getting that framing right shaped every architectural decision.

**Domain age in a demo context**

The domain age scenario (lodash@4.17.23, modelling the Axios attack pattern) required
a synthetic domain age injection. Real attacker domains from the March 2026 attack
cannot be re-deployed, and registering a new attacker domain for a demo would be
inappropriate. The synthetic injection simulates what the Elastic cache would return
for a real attacker domain registered 3 days before publish. The enrichment pipeline,
confidence scoring, and override logic are identical whether the domain age comes from
a live RDAP lookup, an Elastic cache hit, or a synthetic injection.

**MCP as the right interface**

The decision to use MCP rather than direct function calls was deliberate. MCP makes the
agent pattern legible — the tools are named, typed, and callable by any agent that
speaks the protocol. In a sovereign on-premises deployment the same three tools would
resolve against a local npm registry mirror and a local WHOIS cache in Elastic. The
protocol is the same. Only the endpoints change.

---

## Accomplishments

- 4/4 demo scenarios passing with validated output (see `docs/demo-evidence-2026-05-22.md`)
- The lodash@4.17.22 scenario demonstrates the core thesis: Gemini returns SAFE, MCP
  overrides to MALICIOUS, attack caught entirely from registry metadata
- Elastic cache working correctly — first call fetches live, subsequent calls sub-500ms
- Live deployment on Cloud Run with evidence trail dashboard

---

## What We Learned

The most important finding is empirical: for manifest-only hijack attacks, the signal
is not in the package. No amount of model depth or fine-tuning resolves this class
without external metadata. The MCP sidecar is not an enhancement to the AI classifier —
it is the only mechanism that can catch this attack class at all.

The confidence scoring approach — weighted signals assembled into a single score that
drives the override decision — turned out to be the right abstraction. It makes the
agent's reasoning transparent and auditable, and it gives security teams a single
threshold to configure rather than a set of opaque model parameters.

---

## What's Next

**Production integration**

The sidecar currently runs as a standalone service. The next step is wiring it into a
full registry proxy as a signal injection layer — protocol-agnostic, so MCP is one
backend and direct HTTP calls to local mirrors is another. The confidence scoring and
prompt injection logic is identical regardless of which backend is active.

**Sovereign deployment**

In air-gapped enterprise environments, the three MCP tools resolve against local
infrastructure — a local npm registry mirror, a local WHOIS cache in Elastic, an
internal GitLab mirror. No architecture change required. This is the deployment model
for regulated environments where no external API calls are permitted.

**PyPI support**

The same architecture applies to Python packages. The signal set is slightly different
(PyPI has its own provenance model) but the MCP tool pattern and confidence scoring
approach are identical.

**CISO risk tolerance interface**

The `SIDECAR_MODE` environment variable (strict / balanced / permissive) exposes the
block and escalate thresholds as a configurable risk tolerance setting. The next step
is surfacing this in the dashboard so security teams can tune it without touching
configuration files.

---

## Built With

- Gemini 2.5 Flash (Vertex AI)
- Elastic Cloud
- Google Cloud Run
- Google Cloud Agent Builder
- Python / Flask
- Model Context Protocol (MCP)
