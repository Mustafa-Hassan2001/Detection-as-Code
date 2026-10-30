"""Shared helpers for the Detection-as-Code tooling.

Everything here is deliberately small and dependency-light (PyYAML only) so the tools run
the same way on a laptop, in WSL and in GitHub Actions.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "rules"
MAPPING_FILE = REPO_ROOT / "mapping" / "detections.yml"
ATTACK_DIR = REPO_ROOT / "mapping" / "attack"
CONFIG_DIR = REPO_ROOT / "config"

# The ATT&CK release every tool validates against. Changing it is a reviewed change:
# run `make attack-data ATTACK_VERSION=x.y`, commit the new file, fix what breaks.
# DAC_ATTACK_VERSION is only overridden by the scheduled "ATT&CK watch" workflow, which
# checks whether the rules would still validate against a newer release.
ATTACK_VERSION = os.environ.get("DAC_ATTACK_VERSION", "20.0")
ATTACK_FILE = ATTACK_DIR / f"enterprise-attack-v{ATTACK_VERSION}.json"

TECHNIQUE_TAG_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$")


@dataclass
class Rule:
    path: Path
    data: dict[str, Any]
    techniques: list[str] = field(default_factory=list)  # upper-case, e.g. T1059.001
    tactic_tags: list[str] = field(default_factory=list)  # ATT&CK shortnames, e.g. execution

    @property
    def stem(self) -> str:
        return self.path.stem

    @property
    def rel(self) -> str:
        return self.path.relative_to(REPO_ROOT).as_posix()

    @property
    def logsource(self) -> dict[str, str]:
        return self.data.get("logsource") or {}


def load_rule(path: Path) -> Rule:
    with path.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: not a YAML mapping")
    rule = Rule(path=path, data=data)
    for tag in data.get("tags") or []:
        tag = str(tag)
        m = TECHNIQUE_TAG_RE.match(tag)
        if m:
            rule.techniques.append(m.group(1).upper())
        elif tag.startswith("attack."):
            rule.tactic_tags.append(tag.split(".", 1)[1])
    return rule


def rule_paths() -> list[Path]:
    return sorted(RULES_DIR.rglob("*.yml"))


def load_rules() -> list[Rule]:
    return [load_rule(p) for p in rule_paths()]


def load_mapping() -> dict[str, Any]:
    with MAPPING_FILE.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def load_attack() -> dict[str, Any]:
    if not ATTACK_FILE.exists():
        raise SystemExit(
            f"Pinned ATT&CK data {ATTACK_FILE} not found - run `make attack-data`."
        )
    with ATTACK_FILE.open(encoding="utf-8") as fh:
        return json.load(fh)


def prime_pysigma_attack_cache(attack: dict[str, Any] | None = None) -> None:
    """Make pySigma (and therefore sigma-cli) use the pinned ATT&CK release.

    pySigma >= 1.0 downloads the *latest* enterprise-attack.json on first use and keeps it
    in a disk cache (~/.cache/pysigma/mitre_attack). We pre-fill that cache from the
    pinned extract so `sigma check` (attacktag validator) and the Elastic SIEM-rule
    output use exactly the same ATT&CK version as our own validator - and work offline.
    """
    from sigma.data import mitre_attack  # imported lazily: only needed with pySigma installed

    attack = attack or load_attack()
    data = {
        "mitre_attack_version": attack["version"],
        "mitre_attack_tactics": {tid: t["shortname"] for tid, t in attack["tactics"].items()},
        "mitre_attack_techniques": {tid: t["name"] for tid, t in attack["techniques"].items()},
        "mitre_attack_techniques_tactics_mapping": {
            tid: t["tactics"] for tid, t in attack["techniques"].items()
        },
        "mitre_attack_intrusion_sets": {},
        "mitre_attack_software": {},
        "mitre_attack_datasources": {},
        "mitre_attack_mitigations": {},
    }
    mitre_attack._get_cache().set("mitre_attack_data", data)  # noqa: SLF001 (pinned pySigma)
