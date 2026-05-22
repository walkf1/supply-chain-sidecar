"""Elastic MCP Server — Supply Chain Sidecar.

Exposes three tools via the Model Context Protocol:
  - get_git_tag(name, version)
  - get_domain_age(domain)
  - get_publish_method(name, version)

Each tool first checks the Elastic index for a cached result.
On cache miss it fetches live from npm registry / WHOIS and indexes the result.
"""

import os
import time
import hashlib
import requests
from datetime import datetime, timezone
from elasticsearch import Elasticsearch

ELASTIC_CLOUD_ID = os.getenv("ELASTIC_CLOUD_ID", "")
ELASTIC_API_KEY = os.getenv("ELASTIC_API_KEY", "")
ELASTIC_INDEX = os.getenv("ELASTIC_INDEX", "supply-chain-sidecar")
NPM_REGISTRY = os.getenv("NPM_UPSTREAM", "https://registry.npmjs.org")  # always HTTPS
CACHE_TTL_SECONDS = int(os.getenv("CACHE_TTL_SECONDS", "3600"))

_es = None


def _get_es() -> Elasticsearch:
    global _es
    if _es is None:
        _es = Elasticsearch(cloud_id=ELASTIC_CLOUD_ID, api_key=ELASTIC_API_KEY)
    return _es


def _cache_key(tool: str, *args) -> str:
    raw = f"{tool}:{':'.join(str(a) for a in args)}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _get_cached(key: str) -> dict | None:
    try:
        es = _get_es()
        result = es.get(index=ELASTIC_INDEX, id=key)
        doc = result["_source"]
        if time.time() - doc.get("cached_at", 0) < CACHE_TTL_SECONDS:
            return doc
    except Exception as e:
        msg = str(e)
        if "NotFoundError" not in msg and "404" not in msg:
            print(f"[elastic] cache read miss ({key}): {msg}")
    return None


def _set_cached(key: str, doc: dict) -> None:
    try:
        es = _get_es()
        doc["cached_at"] = time.time()
        es.index(index=ELASTIC_INDEX, id=key, document=doc)
    except Exception as e:
        print(f"[elastic] cache write failed ({key}): {e}")


def get_git_tag(name: str, version: str) -> dict:
    """Check whether a git tag exists for this package version."""
    key = _cache_key("git_tag", name, version)
    cached = _get_cached(key)
    if cached:
        cached["source"] = "cache"
        return cached

    result = {"exists": False, "status": "missing", "source": "live"}
    try:
        resp = requests.get(f"{NPM_REGISTRY}/{name}/{version}", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            git_head = data.get("gitHead")
            result["exists"] = bool(git_head)
            result["status"] = "before_publish" if git_head else "missing"
            result["git_head"] = git_head
            result["publish_time"] = data.get("time", {}).get(version)
            repo = data.get("repository", {})
            result["repository"] = repo.get("url", "") if isinstance(repo, dict) else str(repo)
    except Exception as e:
        result["status"] = "unknown"
        result["error"] = str(e)

    _set_cached(key, result)
    return result


def get_domain_age(domain: str) -> dict:
    """Get the age of a domain in days since registration via RDAP."""
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
    key = _cache_key("domain_age", domain)
    cached = _get_cached(key)
    if cached:
        cached["source"] = "cache"
        return cached

    result = {"domain": domain, "age_days": None, "registered": None, "source": "live"}
    try:
        resp = requests.get(f"https://rdap.org/domain/{domain}", timeout=5)
        if resp.status_code == 200:
            for event in resp.json().get("events", []):
                if event.get("eventAction") == "registration":
                    reg_str = event.get("eventDate", "")
                    if reg_str:
                        reg_date = datetime.fromisoformat(reg_str.replace("Z", "+00:00"))
                        result["age_days"] = (datetime.now(timezone.utc) - reg_date).days
                        result["registered"] = reg_str
                    break
    except Exception as e:
        result["error"] = str(e)

    _set_cached(key, result)
    return result


def get_publish_method(name: str, version: str) -> dict:
    """Determine whether a package was published via OIDC CI-CD or manual token."""
    key = _cache_key("publish_method", name, version)
    cached = _get_cached(key)
    if cached:
        cached["source"] = "cache"
        return cached

    result = {"method": "unknown", "provenance": None, "source": "live"}
    try:
        resp = requests.get(f"{NPM_REGISTRY}/{name}/{version}", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            provenance = data.get("dist", {}).get("provenance") or data.get("provenance")
            result["method"] = "oidc" if provenance else "manual_token"
            result["provenance"] = provenance
    except Exception as e:
        result["error"] = str(e)

    _set_cached(key, result)
    return result


TOOLS = {
    "get_git_tag": get_git_tag,
    "get_domain_age": get_domain_age,
    "get_publish_method": get_publish_method,
}


def call_tool(name: str, **kwargs) -> dict:
    if name not in TOOLS:
        return {"error": f"Unknown tool: {name}"}
    return TOOLS[name](**kwargs)
