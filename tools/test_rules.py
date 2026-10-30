#!/usr/bin/env python3
"""Unit-test every Sigma rule against the synthetic sample logs.

How it works (the same idea as Zircolite):
  1. Each JSONL sample file is loaded into its own in-memory SQLite table. Columns are
     declared COLLATE NOCASE because Sigma string matching is case-insensitive.
  2. Each rule is converted to SQL with pySigma's SQLite backend - the same pySigma
     engine that sigma-cli uses for the SIEM conversions. Windows rules go through the
     standard `sysmon` processing pipeline, which adds the EventID condition for the log
     source category (e.g. process_access -> EventID 10), so the pipeline is tested too.
  3. The query runs against the rule's sample file. The matched _sample_id values are
     compared with mapping/detections.yml:
         expected_matches        must all be hit (else: FALSE NEGATIVE -> fail)
         known_false_positives   may be hit (documented FP, reported, not a failure)
         anything else           unexpected hit (FALSE POSITIVE -> fail)
  4. Corpus-level checks: every event labelled "malicious" must be detected by at least
     one rule, and every hit on a "benign" event must be a documented false positive.

Outputs a console report, and with --report a Markdown + JSON summary under build/.

    python tools/test_rules.py [--report]
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dac_common import REPO_ROOT, load_mapping, load_rule  # noqa: E402

from sigma.backends.sqlite import sqliteBackend  # noqa: E402
from sigma.collection import SigmaCollection  # noqa: E402
from sigma.pipelines.sysmon import sysmon_pipeline  # noqa: E402

BUILD_DIR = REPO_ROOT / "build"


def regexp(pattern: str, value) -> bool:
    """SQLite REGEXP implementation. Sigma `re` is an unanchored search."""
    if value is None:
        return False
    return re.search(pattern, str(value)) is not None


def load_events(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def build_table(conn: sqlite3.Connection, events: list[dict]) -> None:
    columns: list[str] = []
    for ev in events:
        for key in ev:
            if key not in columns:
                columns.append(key)
    cols_sql = ", ".join(f'"{c}" COLLATE NOCASE' for c in columns)
    conn.execute("DROP TABLE IF EXISTS logs")
    conn.execute(f"CREATE TABLE logs ({cols_sql})")
    placeholders = ", ".join("?" for _ in columns)
    rows = []
    for ev in events:
        row = []
        for c in columns:
            v = ev.get(c, "")
            # Missing fields become '' rather than NULL: in SQL, NOT (NULL LIKE x) is NULL
            # (no match), whereas SIEM queries treat "field absent" as "filter not hit".
            # Booleans follow the Zircolite convention ('true'/'false') used by the backend.
            if isinstance(v, bool):
                v = "true" if v else "false"
            row.append(v)
        rows.append(row)
    conn.executemany(f'INSERT INTO logs ({", ".join(chr(34) + c + chr(34) for c in columns)}) '
                     f"VALUES ({placeholders})", rows)


def rule_to_sql(rule_path: Path) -> list[str]:
    rule = load_rule(rule_path)
    pipeline = sysmon_pipeline() if rule.logsource.get("product") == "windows" else None
    backend = sqliteBackend(processing_pipeline=pipeline)
    collection = SigmaCollection.from_yaml(rule_path.read_text(encoding="utf-8"))
    return backend.convert(collection)


def main() -> int:
    ap = argparse.ArgumentParser(description="Test Sigma rules against synthetic sample logs")
    ap.add_argument("--report", action="store_true", help="write build/test-report.{md,json}")
    ap.add_argument("-v", "--verbose", action="store_true", help="print generated SQL")
    args = ap.parse_args()

    mapping = load_mapping()
    conn = sqlite3.connect(":memory:")
    conn.create_function("regexp", 2, regexp, deterministic=True)

    corpus: dict[str, dict] = {}  # sample_id -> event (across all files)
    loaded_file = None
    hits_by_sample: dict[str, list[str]] = {}
    results = []
    failures = 0

    # Sort by sample file so each table is built once.
    detections = sorted(mapping["detections"], key=lambda d: d["sample_data"]["file"])
    sample_files = {d["sample_data"]["file"] for d in detections}
    for f in sample_files:
        for ev in load_events(REPO_ROOT / f):
            corpus[ev["_sample_id"]] = ev

    for det in detections:
        sample_file = det["sample_data"]["file"]
        if sample_file != loaded_file:
            build_table(conn, load_events(REPO_ROOT / sample_file))
            loaded_file = sample_file

        rule_path = REPO_ROOT / det["rule"]
        expected = set(det["sample_data"].get("expected_matches", []))
        known_fp = set(det["sample_data"].get("known_false_positives", []))
        try:
            queries = rule_to_sql(rule_path)
        except Exception as exc:  # conversion error is a test failure, not a crash
            results.append({"rule": det["rule"], "status": "ERROR", "error": str(exc)})
            failures += 1
            print(f"ERROR  {rule_path.stem}: conversion failed: {exc}")
            continue

        hits: set[str] = set()
        for q in queries:
            if args.verbose:
                print(f"       SQL: {q}")
            q = q.replace("SELECT *", 'SELECT "_sample_id"', 1)
            hits.update(r[0] for r in conn.execute(q))

        for sid in hits:
            hits_by_sample.setdefault(sid, []).append(rule_path.stem)

        false_neg = sorted(expected - hits)
        false_pos = sorted(hits - expected - known_fp)
        accepted_fp = sorted(hits & known_fp)
        ok = not false_neg and not false_pos
        failures += 0 if ok else 1
        status = "PASS" if ok else "FAIL"
        detail = f"hits={sorted(hits)}"
        if false_neg:
            detail += f" MISSED={false_neg}"
        if false_pos:
            detail += f" UNEXPECTED={false_pos}"
        if accepted_fp:
            detail += f" known_fp={accepted_fp}"
        print(f"{status:5}  {rule_path.stem}: {detail}")
        results.append({
            "rule": det["rule"], "status": status, "hits": sorted(hits),
            "expected": sorted(expected), "missed": false_neg,
            "unexpected": false_pos, "known_false_positives_hit": accepted_fp,
        })

    # ------------------------------------------------------------ corpus-level checks
    print()
    undetected = sorted(
        sid for sid, ev in corpus.items() if ev["_label"] == "malicious" and sid not in hits_by_sample
    )
    benign = [sid for sid, ev in corpus.items() if ev["_label"] == "benign"]
    benign_hit = sorted(sid for sid in benign if sid in hits_by_sample)
    documented_fp = {
        sid for d in mapping["detections"] for sid in d["sample_data"].get("known_false_positives", [])
    }
    undocumented_benign_hits = [sid for sid in benign_hit if sid not in documented_fp]
    malicious = [sid for sid, ev in corpus.items() if ev["_label"] == "malicious"]

    print(f"Malicious sample events : {len(malicious)}  detected: {len(malicious) - len(undetected)}")
    print(f"Benign sample events    : {len(benign)}  alerted on: {len(benign_hit)} "
          f"(documented FP: {len(benign_hit) - len(undocumented_benign_hits)})")
    if undetected:
        print(f"FAIL   malicious events detected by no rule: {undetected}")
        failures += 1
    if undocumented_benign_hits:
        print(f"FAIL   benign events alerted on without a documented FP: {undocumented_benign_hits}")
        failures += 1

    if args.report:
        BUILD_DIR.mkdir(exist_ok=True)
        summary = {
            "rules_tested": len(results),
            "rules_passed": sum(1 for r in results if r["status"] == "PASS"),
            "malicious_events": len(malicious),
            "malicious_detected": len(malicious) - len(undetected),
            "benign_events": len(benign),
            "benign_alerted": len(benign_hit),
            "results": results,
        }
        (BUILD_DIR / "test-report.json").write_text(json.dumps(summary, indent=2) + "\n")
        lines = [
            "# Rule test report (synthetic sample data)",
            "",
            "Generated by `tools/test_rules.py`. Synthetic data proves rule *logic*; it says",
            "nothing about real-world false-positive rates (see docs/results.md).",
            "",
            f"- Rules passed: {summary['rules_passed']}/{summary['rules_tested']}",
            f"- Malicious sample events detected: {summary['malicious_detected']}/{summary['malicious_events']}",
            f"- Benign sample events alerted on: {summary['benign_alerted']}/{summary['benign_events']}"
            " (all must be documented false positives)",
            "",
            "| Rule | Result | Hits | Known FP hit |",
            "|---|---|---|---|",
        ]
        for r in results:
            lines.append(
                f"| `{Path(r['rule']).stem}` | {r['status']} | {', '.join(r.get('hits', []))} "
                f"| {', '.join(r.get('known_false_positives_hit', [])) or '-'} |"
            )
        (BUILD_DIR / "test-report.md").write_text("\n".join(lines) + "\n")
        print(f"\nReport written to {BUILD_DIR.relative_to(REPO_ROOT)}/test-report.md")

    print()
    print("RESULT: " + ("OK" if failures == 0 else f"{failures} failure(s)"))
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
