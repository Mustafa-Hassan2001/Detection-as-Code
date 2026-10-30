#!/usr/bin/env python3
"""Download a pinned MITRE ATT&CK Enterprise release and write a compact extract.

The full STIX bundle is ~55 MB; the tools only need technique IDs, names, tactics and the
list of revoked/deprecated IDs. The extract (~100 KB) is committed so that validation,
coverage and CI are deterministic and work offline. The SHA-256 of the source bundle is
recorded so a reviewer can verify the extract came from the official release.

Usage:  python tools/update_attack_data.py [--version 20.0]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent))
from dac_common import ATTACK_DIR, ATTACK_VERSION  # noqa: E402

URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack-{version}.json"
)


def ext_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--version", default=ATTACK_VERSION)
    args = ap.parse_args()

    url = URL.format(version=args.version)
    print(f"Downloading {url}")
    with urllib.request.urlopen(url, timeout=120) as resp:  # noqa: S310 (fixed https URL)
        raw = resp.read()
    bundle = json.loads(raw)

    tactics: dict[str, dict] = {}
    shortname_by_ref: dict[str, str] = {}
    techniques: dict[str, dict] = {}
    retired: dict[str, str] = {}
    tactic_order: list[str] = []
    matrix_refs: list[str] = []

    for obj in bundle["objects"]:
        otype = obj.get("type")
        if otype == "x-mitre-matrix" and not obj.get("revoked"):
            matrix_refs = obj.get("tactic_refs", [])
        if otype == "x-mitre-tactic" and not obj.get("revoked") and not obj.get("x_mitre_deprecated"):
            tid = ext_id(obj)
            tactics[tid] = {"shortname": obj["x_mitre_shortname"], "name": obj["name"]}
            shortname_by_ref[obj["id"]] = tid
        if otype == "attack-pattern":
            tid = ext_id(obj)
            if not tid:
                continue
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                retired[tid] = "revoked" if obj.get("revoked") else "deprecated"
                continue
            techniques[tid] = {
                "name": obj["name"],
                "tactics": [
                    p["phase_name"]
                    for p in obj.get("kill_chain_phases", [])
                    if p.get("kill_chain_name") == "mitre-attack"
                ],
                "platforms": sorted(obj.get("x_mitre_platforms", [])),
            }

    tactic_order = [shortname_by_ref[r] for r in matrix_refs if r in shortname_by_ref]
    # An ID can be both retired (old object) and active (re-used); active wins.
    retired = {k: v for k, v in retired.items() if k not in techniques}

    out = {
        "source": url,
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "version": args.version,
        "tactic_order": tactic_order,
        "tactics": dict(sorted(tactics.items())),
        "techniques": dict(sorted(techniques.items())),
        "retired": dict(sorted(retired.items())),
    }
    ATTACK_DIR.mkdir(parents=True, exist_ok=True)
    target = ATTACK_DIR / f"enterprise-attack-v{args.version}.json"
    target.write_text(json.dumps(out, indent=1, sort_keys=False) + "\n", encoding="utf-8")
    print(
        f"Wrote {target} ({len(techniques)} techniques, {len(tactics)} tactics, "
        f"{len(retired)} retired IDs)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
