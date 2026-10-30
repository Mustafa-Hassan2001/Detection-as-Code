#!/usr/bin/env python3
"""LAB MODE: run the converted queries against your SIEM and report hits per rule.

Sends every converted/<target>/lucene/*.lucene query to an Elasticsearch- or
OpenSearch-compatible `_search` endpoint (Wazuh indexer, Elastic) as a query_string query
over a time window, and prints how many documents each rule matched. Use it right after
running the atomics to fill in docs/results.md.

Credentials are read from the environment - never put them in the repo:
    export DAC_SIEM_URL=https://10.10.0.20:9200
    export DAC_SIEM_USER=admin
    export DAC_SIEM_PASSWORD='...'
    python tools/hunt_lab.py --target wazuh --since 2h --ca-cert ~/securenet/root-ca.pem
    python tools/hunt_lab.py --target wazuh --since 2h --insecure     # self-signed lab cert

Writes build/lab-hunt-<target>.md (git-ignored).
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULTS = {
    "wazuh": {"index": "wazuh-archives-*,wazuh-alerts-*", "time_field": "timestamp"},
    "elastic": {"index": "logs-*,winlogbeat-*,filebeat-*,auditbeat-*", "time_field": "@timestamp"},
}


def search(url: str, index: str, body: dict, ctx: ssl.SSLContext, auth: str | None) -> dict:
    req = urllib.request.Request(
        f"{url.rstrip('/')}/{index}/_search", data=json.dumps(body).encode(), method="POST",
        headers={"Content-Type": "application/json"},
    )
    if auth:
        req.add_header("Authorization", f"Basic {auth}")
    with urllib.request.urlopen(req, context=ctx, timeout=60) as resp:  # noqa: S310 (user-supplied lab URL)
        return json.load(resp)


def main() -> int:
    ap = argparse.ArgumentParser(description="Run converted rules against a lab SIEM")
    ap.add_argument("--target", choices=sorted(DEFAULTS), required=True)
    ap.add_argument("--url", default=os.environ.get("DAC_SIEM_URL"))
    ap.add_argument("--index", help="index pattern (default depends on target)")
    ap.add_argument("--time-field", help="timestamp field (default depends on target)")
    ap.add_argument("--since", default="24h", help="look-back window, e.g. 2h, 7d")
    ap.add_argument("--ca-cert", help="CA bundle for the SIEM's TLS certificate")
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification (lab only)")
    a = ap.parse_args()
    if not a.url:
        sys.exit("Set DAC_SIEM_URL or pass --url")

    index = a.index or DEFAULTS[a.target]["index"]
    time_field = a.time_field or DEFAULTS[a.target]["time_field"]
    user, pw = os.environ.get("DAC_SIEM_USER"), os.environ.get("DAC_SIEM_PASSWORD")
    auth = base64.b64encode(f"{user}:{pw}".encode()).decode() if user else None
    ctx = ssl.create_default_context(cafile=a.ca_cert)
    if a.insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    rows, errors = [], 0
    for qfile in sorted((REPO_ROOT / "converted" / a.target / "lucene").glob("*.lucene")):
        query = qfile.read_text(encoding="utf-8").strip()
        body = {
            "size": 0,
            "track_total_hits": True,
            "query": {"bool": {"must": [{"query_string": {"query": query, "analyze_wildcard": True}}],
                               "filter": [{"range": {time_field: {"gte": f"now-{a.since}"}}}]}},
        }
        try:
            hits = search(a.url, index, body, ctx, auth)["hits"]["total"]["value"]
            rows.append((qfile.stem, str(hits)))
            print(f"{hits:>7}  {qfile.stem}")
        except (urllib.error.URLError, KeyError, json.JSONDecodeError) as exc:
            errors += 1
            rows.append((qfile.stem, f"ERROR: {exc}"))
            print(f"  ERROR  {qfile.stem}: {exc}")

    out = REPO_ROOT / "build" / f"lab-hunt-{a.target}.md"
    out.parent.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [f"# Lab hunt - {a.target} - {stamp}", "",
             f"Index `{index}`, window `now-{a.since}`. Hits = matching documents.", "",
             "| Rule | Hits |", "|---|---:|"] + [f"| `{r}` | {h} |" for r, h in rows]
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\nWrote {out.relative_to(REPO_ROOT)}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
