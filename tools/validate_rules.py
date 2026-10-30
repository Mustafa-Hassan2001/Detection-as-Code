#!/usr/bin/env python3
"""Project-specific rule validation (runs after `sigma check`).

`sigma check` answers "is this a well-formed Sigma rule?". This script answers "does the
rule meet THIS repository's quality bar?":

  Metadata      required fields present and non-empty, UUID id unique, valid status/level,
                ISO date, description and false-positive notes actually written,
                file name follows the naming convention for its log source.
  Attribution   a rule declaring `related: type: derived` (adapted from a SigmaHQ rule) must
                carry `license: DRL-1.1`, name the original authors in `author`, and link the
                upstream rule in `references`, as the Detection Rule License 1.1 requires;
                `type: similar` must link the upstream rule it resembles.
  ATT&CK        at least one technique tag and one tactic tag; every technique exists in
                the PINNED ATT&CK release (revoked/deprecated IDs are rejected with a hint);
                tactic tags are real tactics; every technique is tagged with at least one
                of its own tactics and every tactic tag is backed by a technique; the
                references include the attack.mitre.org page of each technique.
  Mapping       mapping/detections.yml covers every rule exactly once, and agrees with the
                rule (UUID, techniques, logsource); the atomic test exists and targets one
                of the rule's techniques; sample data file and sample IDs exist and are
                labelled consistently (expected = malicious, known FP = benign).

Usage:
    python tools/validate_rules.py                 # human-readable
    python tools/validate_rules.py --github        # also emit GitHub Actions annotations
    python tools/validate_rules.py path/to/rules   # validate another rules directory
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
import uuid
from collections import Counter
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dac_common import (  # noqa: E402
    ATTACK_VERSION,
    REPO_ROOT,
    RULES_DIR,
    Rule,
    load_attack,
    load_mapping,
    load_rule,
)

REQUIRED_FIELDS = [
    "title", "id", "status", "description", "references", "author", "date",
    "tags", "logsource", "detection", "falsepositives", "level",
]
STATUSES = {"stable", "test", "experimental", "deprecated", "unsupported"}
LEVELS = {"informational", "low", "medium", "high", "critical"}
LAB_STATES = {"not-run", "fired", "not-fired", "partial"}
MIN_DESCRIPTION = 80  # characters - forces an actual explanation, not a title restatement

# File-name prefix expected for each log source (keeps the tree navigable).
FILENAME_PREFIX = [
    ({"product": "windows", "category": "process_creation"}, "proc_creation_win_"),
    ({"product": "windows", "category": "process_access"}, "proc_access_win_"),
    ({"product": "windows", "category": "registry_set"}, "registry_set_win_"),
    ({"product": "linux", "category": "process_creation"}, "proc_creation_lnx_"),
    ({"product": "linux", "service": "auditd"}, "lnx_auditd_"),
    ({"product": "zeek"}, "zeek_"),
]
FILENAME_RE = re.compile(r"^[a-z0-9_]+\.yml$")


class Report:
    def __init__(self, github: bool) -> None:
        self.github = github
        self.errors: list[tuple[str, str]] = []

    def error(self, where: str, msg: str) -> None:
        self.errors.append((where, msg))
        print(f"ERROR {where}: {msg}")
        if self.github:
            print(f"::error file={where}::{msg}")


def attack_url(tid: str) -> str:
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


def check_rule(rule: Rule, attack: dict, rep: Report) -> None:
    d, where = rule.data, rule.rel
    for f in REQUIRED_FIELDS:
        if f not in d or d[f] in (None, "", [], {}):
            rep.error(where, f"missing or empty required field '{f}'")

    try:
        if str(uuid.UUID(str(d.get("id")))) != str(d.get("id")):
            raise ValueError
    except ValueError:
        rep.error(where, f"id '{d.get('id')}' is not a canonical UUID")

    if d.get("status") not in STATUSES:
        rep.error(where, f"status '{d.get('status')}' not in {sorted(STATUSES)}")
    if d.get("level") not in LEVELS:
        rep.error(where, f"level '{d.get('level')}' not in {sorted(LEVELS)}")

    date = d.get("date")
    if not isinstance(date, dt.date):
        try:
            dt.date.fromisoformat(str(date))
        except ValueError:
            rep.error(where, f"date '{date}' is not YYYY-MM-DD")

    if len(str(d.get("description", "")).strip()) < MIN_DESCRIPTION:
        rep.error(where, f"description shorter than {MIN_DESCRIPTION} characters - explain the logic")
    fps = d.get("falsepositives") or []
    if not isinstance(fps, list) or not all(str(x).strip() for x in fps):
        rep.error(where, "falsepositives must be a non-empty list of written notes")
    elif any(str(x).strip().lower() == "unknown" for x in fps):
        rep.error(where, "falsepositives 'Unknown' is not accepted - describe the expected noise")

    # --- naming convention
    if not FILENAME_RE.match(rule.path.name):
        rep.error(where, "file name must be lower-case snake_case ending in .yml")
    ls = rule.logsource
    for cond, prefix in FILENAME_PREFIX:
        if all(ls.get(k) == v for k, v in cond.items()):
            if not rule.path.name.startswith(prefix):
                rep.error(where, f"file name should start with '{prefix}' for logsource {cond}")
            break
    else:
        rep.error(where, f"logsource {ls} has no naming convention - extend FILENAME_PREFIX")

    # --- attribution (Detection Rule License 1.1 for rules adapted from SigmaHQ)
    related = d.get("related") or []
    kinds = {str(r.get("type")) for r in related if isinstance(r, dict)}
    upstream_refs = [r for r in (d.get("references") or []) if "github.com/SigmaHQ/sigma/" in str(r)]
    if "derived" in kinds:
        if not str(d.get("license", "")).startswith("DRL"):
            rep.error(where, "derived from a SigmaHQ rule: add 'license: DRL-1.1'")
        if "SigmaHQ" not in str(d.get("author", "")):
            rep.error(where, "derived from a SigmaHQ rule: 'author' must name the original SigmaHQ authors")
    if kinds & {"derived", "similar"} and len(upstream_refs) < sum(
            1 for r in related if isinstance(r, dict) and r.get("type") in ("derived", "similar")):
        rep.error(where, "each related upstream rule needs its SigmaHQ URL in 'references'")

    # --- ATT&CK
    techniques, tactics = attack["techniques"], attack["tactics"]
    tactic_shortnames = {t["shortname"] for t in tactics.values()}
    if not rule.techniques:
        rep.error(where, "no ATT&CK technique tag (attack.tXXXX[.YYY])")
    if not rule.tactic_tags:
        rep.error(where, "no ATT&CK tactic tag (e.g. attack.persistence)")

    for tag in rule.tactic_tags:
        if tag not in tactic_shortnames:
            rep.error(where, f"attack.{tag} is not a tactic in ATT&CK v{ATTACK_VERSION}")

    refs = [str(r) for r in d.get("references") or []]
    for tid in rule.techniques:
        if tid not in techniques:
            hint = attack["retired"].get(tid)
            why = f"is {hint} in" if hint else "does not exist in"
            rep.error(where, f"{tid} {why} ATT&CK v{ATTACK_VERSION}")
            continue
        own = set(techniques[tid]["tactics"])
        if not own & set(rule.tactic_tags):
            rep.error(where, f"{tid} belongs to tactic(s) {sorted(own)} but none is tagged")
        if not any(r.rstrip("/") + "/" == attack_url(tid) for r in refs):
            rep.error(where, f"references should include {attack_url(tid)}")
    for tag in rule.tactic_tags:
        backed = any(tag in techniques.get(t, {}).get("tactics", []) for t in rule.techniques)
        if tag in tactic_shortnames and not backed:
            rep.error(where, f"tactic attack.{tag} is not supported by any tagged technique")


def check_mapping(rules: list[Rule], attack: dict, rep: Report) -> None:
    where = "mapping/detections.yml"
    mapping = load_mapping()
    if str(mapping.get("attack_version")) != ATTACK_VERSION:
        rep.error(where, f"attack_version {mapping.get('attack_version')} != pinned {ATTACK_VERSION}")

    by_path = {r.rel: r for r in rules}
    seen = Counter(d.get("rule") for d in mapping.get("detections", []))
    for path, n in seen.items():
        if n > 1:
            rep.error(where, f"{path} is mapped {n} times")
    for path in by_path:
        if path not in seen:
            rep.error(where, f"rule {path} has no entry in the mapping")

    sample_cache: dict[str, dict[str, dict]] = {}
    for det in mapping.get("detections", []):
        path = det.get("rule")
        rule = by_path.get(path)
        if rule is None:
            rep.error(where, f"mapped rule {path} does not exist")
            continue
        if str(det.get("rule_id")) != str(rule.data.get("id")):
            rep.error(where, f"{path}: rule_id {det.get('rule_id')} != rule id {rule.data.get('id')}")
        if sorted(det.get("techniques", [])) != sorted(rule.techniques):
            rep.error(where, f"{path}: techniques {det.get('techniques')} != rule tags {rule.techniques}")
        if (det.get("log_source") or {}).get("sigma") != rule.logsource:
            rep.error(where, f"{path}: log_source.sigma != rule logsource {rule.logsource}")
        if det.get("lab_validation") not in LAB_STATES:
            rep.error(where, f"{path}: lab_validation must be one of {sorted(LAB_STATES)}")
        for key in ("telemetry", "collection"):
            if not (det.get("log_source") or {}).get(key):
                rep.error(where, f"{path}: log_source.{key} is empty")

        # --- emulation / atomic
        emu = det.get("emulation") or {}
        atomic_path = REPO_ROOT / str(emu.get("atomic", ""))
        if not emu.get("atomic") or not atomic_path.is_file():
            rep.error(where, f"{path}: atomic file {emu.get('atomic')} not found")
        else:
            atomic = yaml.safe_load(atomic_path.read_text(encoding="utf-8"))
            if atomic.get("attack_technique") not in rule.techniques:
                rep.error(where, f"{path}: atomic technique {atomic.get('attack_technique')} "
                                 f"is not one of the rule's techniques")
            names = [t.get("name") for t in atomic.get("atomic_tests", [])]
            if emu.get("test") not in names:
                rep.error(where, f"{path}: test '{emu.get('test')}' not in {emu.get('atomic')} ({names})")
        if not (emu.get("upstream") or {}).get("technique"):
            rep.error(where, f"{path}: emulation.upstream.technique missing")

        # --- sample data
        sd = det.get("sample_data") or {}
        sfile = sd.get("file")
        if not sfile or not (REPO_ROOT / sfile).is_file():
            rep.error(where, f"{path}: sample file {sfile} not found")
            continue
        if sfile not in sample_cache:
            with (REPO_ROOT / sfile).open(encoding="utf-8") as fh:
                evs = [json.loads(line) for line in fh if line.strip()]
            sample_cache[sfile] = {e["_sample_id"]: e for e in evs}
        events = sample_cache[sfile]
        if not sd.get("expected_matches"):
            rep.error(where, f"{path}: expected_matches is empty - every rule needs a positive test")
        for sid in sd.get("expected_matches", []):
            if sid not in events:
                rep.error(where, f"{path}: expected sample {sid} not in {sfile}")
            elif events[sid]["_label"] != "malicious":
                rep.error(where, f"{path}: expected sample {sid} is labelled {events[sid]['_label']}")
        for sid in sd.get("known_false_positives", []):
            if sid not in events:
                rep.error(where, f"{path}: known FP sample {sid} not in {sfile}")
            elif events[sid]["_label"] != "benign":
                rep.error(where, f"{path}: known FP sample {sid} should be labelled benign")


def main() -> int:
    ap = argparse.ArgumentParser(description="Validate rule metadata, ATT&CK tags and mapping")
    ap.add_argument("rules_dir", nargs="?", default=str(RULES_DIR))
    ap.add_argument("--github", action="store_true", help="emit GitHub Actions annotations")
    ap.add_argument("--no-mapping", action="store_true", help="skip mapping checks")
    args = ap.parse_args()

    rep = Report(args.github)
    attack = load_attack()
    rules_dir = Path(args.rules_dir).resolve()
    rules: list[Rule] = []
    for p in sorted(rules_dir.rglob("*.yml")):
        try:
            rules.append(load_rule(p))
        except Exception as exc:  # malformed YAML
            rep.error(p.relative_to(REPO_ROOT).as_posix() if p.is_relative_to(REPO_ROOT) else str(p),
                      f"cannot parse: {exc}")
    if not rules and not rep.errors:
        rep.error(str(rules_dir), "no rules found")

    for rule in rules:
        check_rule(rule, attack, rep)
    for field_name in ("id", "title"):
        counts = Counter(str(r.data.get(field_name)) for r in rules)
        for value, n in counts.items():
            if n > 1:
                rep.error("rules/", f"duplicate {field_name} '{value}' used by {n} rules")
    if not args.no_mapping:
        check_mapping(rules, attack, rep)

    print(
        f"\nValidated {len(rules)} rules against ATT&CK Enterprise v{ATTACK_VERSION}: "
        + ("OK" if not rep.errors else f"{len(rep.errors)} error(s)")
    )
    return 1 if rep.errors else 0


if __name__ == "__main__":
    sys.exit(main())
