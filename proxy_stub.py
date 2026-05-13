"""Supply Chain Sidecar — npm proxy stub."""

import os
import io
import json
import tarfile
import hashlib
import requests
from flask import Flask, Response, request, abort

app = Flask(__name__)
NPM_REGISTRY = os.getenv("NPM_UPSTREAM", "https://registry.npmjs.org")
SIDECAR_URL = os.getenv("SIDECAR_URL", "http://localhost:8080")
PORT = int(os.getenv("PROXY_PORT", 4873))
_cache = {}


@app.route("/<path:package_name>/-/<tarball>")
def proxy_tarball(package_name, tarball):
    try:
        resp = requests.get(f"{NPM_REGISTRY}/{package_name}/-/{tarball}", timeout=10)
        if resp.status_code != 200:
            abort(resp.status_code)
        tarball_bytes = resp.content
    except requests.RequestException as e:
        abort(503, str(e))

    manifest = {}
    try:
        tar = tarfile.open(fileobj=io.BytesIO(tarball_bytes))
        for path in ["package/package.json", "package.json"]:
            try:
                manifest = json.loads(tar.extractfile(path).read().decode())
                break
            except Exception:
                continue
    except Exception:
        pass

    pkg_hash = hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()[:16]
    if pkg_hash in _cache:
        if _cache[pkg_hash] == "MALICIOUS":
            abort(403, "Blocked by Supply Chain Sidecar (cached)")
        return Response(tarball_bytes, mimetype="application/octet-stream",
                        headers={"X-Sidecar-Verdict": "SAFE", "X-Sidecar-Cached": "true"})

    try:
        result = requests.post(f"{SIDECAR_URL}/assess", json={"manifest": manifest}, timeout=10).json()
    except Exception:
        return Response(tarball_bytes, mimetype="application/octet-stream",
                        headers={"X-Sidecar-Verdict": "UNKNOWN"})

    verdict = result.get("verdict", "SAFE")
    _cache[pkg_hash] = verdict

    if verdict == "MALICIOUS":
        abort(403, f"Blocked by Supply Chain Sidecar: {result.get('evidence_summary', '')}")

    return Response(tarball_bytes, mimetype="application/octet-stream",
                    headers={"X-Sidecar-Verdict": verdict,
                             "X-Sidecar-Confidence": str(result.get("confidence", "")),
                             "X-Sidecar-Enriched": str(result.get("enriched", False))})


@app.route("/<path:package_name>")
def proxy_metadata(package_name):
    try:
        resp = requests.get(f"{NPM_REGISTRY}/{package_name}", timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            for v in data.get("versions", {}).values():
                if "dist" in v and "tarball" in v["dist"]:
                    v["dist"]["tarball"] = v["dist"]["tarball"].replace(
                        "https://registry.npmjs.org", f"http://localhost:{PORT}")
            return Response(json.dumps(data), status=200, content_type="application/json")
        return Response(resp.content, status=resp.status_code,
                        content_type=resp.headers.get("content-type"))
    except requests.RequestException as e:
        abort(503, str(e))


if __name__ == "__main__":
    print(f"Supply Chain Sidecar proxy: http://localhost:{PORT}")
    app.run(host="0.0.0.0", port=PORT, threaded=True)
