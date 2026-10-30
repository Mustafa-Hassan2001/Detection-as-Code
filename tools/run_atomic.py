#!/usr/bin/env python3
"""Minimal, safety-guarded runner for the Linux atomics in atomics/ (Atomic Red Team format).

Windows tests: use Invoke-AtomicRedTeam directly - the YAML files are compatible:
    Invoke-AtomicTest T1059.001 -PathToAtomicsFolder C:\\path\\to\\repo\\atomics -ShowDetails
    Invoke-AtomicTest T1059.001 -PathToAtomicsFolder C:\\path\\to\\repo\\atomics
    Invoke-AtomicTest T1059.001 -PathToAtomicsFolder C:\\path\\to\\repo\\atomics -Cleanup

Linux tests: this runner (no PowerShell needed) or Invoke-AtomicTest under pwsh.

Safety model - the runner refuses to execute unless ALL of these hold:
  * --execute is given (the default is a dry run that only prints the resolved commands),
  * the environment variable DAC_LAB_CONFIRM is set to "isolated-lab",
  * every input argument that names a host/IP/resolver resolves to a loopback or private
    (RFC 1918 / RFC 5737 documentation) address - so a typo cannot point a test at a real
    third-party system.

Examples:
    python tools/run_atomic.py --list
    python tools/run_atomic.py T1059.004                          # dry run
    DAC_LAB_CONFIRM=isolated-lab python tools/run_atomic.py T1059.004 --execute
    DAC_LAB_CONFIRM=isolated-lab python tools/run_atomic.py T1059.004 --cleanup --execute
    python tools/run_atomic.py T1190 -i target_host=10.10.20.10 -i target_port=8080
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import socket
import subprocess
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
ATOMICS = REPO_ROOT / "atomics"
HOST_KEYS = ("host", "ip", "resolver", "target")
CONFIRM_VALUE = "isolated-lab"


def load(technique: str) -> dict:
    path = ATOMICS / technique / f"{technique}.yaml"
    if not path.exists():
        sys.exit(f"No atomic file {path.relative_to(REPO_ROOT)}")
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def list_all() -> None:
    for path in sorted(ATOMICS.glob("T*/T*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        for i, t in enumerate(data["atomic_tests"], 1):
            plat = ",".join(t["supported_platforms"])
            print(f"{data['attack_technique']:10} #{i}  [{plat:7}] {t['name']}")


def check_host(key: str, value: str) -> None:
    try:
        addrs = {ipaddress.ip_address(value)}
    except ValueError:
        try:
            addrs = {ipaddress.ip_address(ai[4][0]) for ai in socket.getaddrinfo(value, None)}
        except socket.gaierror:
            sys.exit(f"REFUSED: input '{key}={value}' does not resolve")
    for a in addrs:
        if not (a.is_loopback or a.is_private):
            sys.exit(f"REFUSED: input '{key}={value}' resolves to {a}, which is not a loopback/"
                     "private lab address. Atomics may only target the isolated lab.")


def resolve(test: dict, overrides: dict[str, str]) -> tuple[dict[str, str], str, str]:
    args = {k: str(v.get("default", "")) for k, v in (test.get("input_arguments") or {}).items()}
    unknown = set(overrides) - set(args)
    if unknown:
        sys.exit(f"Unknown input argument(s): {sorted(unknown)}; available: {sorted(args)}")
    args.update(overrides)

    def sub(text: str) -> str:
        for k, v in args.items():
            text = text.replace("#{" + k + "}", v)
        return text

    ex = test["executor"]
    return args, sub(ex.get("command", "")), sub(ex.get("cleanup_command", "") or "")


def main() -> int:
    ap = argparse.ArgumentParser(description="Run DAC Linux atomics safely (dry run by default)")
    ap.add_argument("technique", nargs="?", help="e.g. T1059.004")
    ap.add_argument("-n", "--test-number", type=int, help="1-based test number (default: all Linux tests)")
    ap.add_argument("-i", "--input", action="append", default=[], help="override input: key=value")
    ap.add_argument("--cleanup", action="store_true", help="run the cleanup command instead")
    ap.add_argument("--execute", action="store_true", help="actually run (otherwise dry run)")
    ap.add_argument("--list", action="store_true", help="list all atomics")
    a = ap.parse_args()

    if a.list or not a.technique:
        list_all()
        return 0

    overrides = dict(kv.split("=", 1) for kv in a.input)
    data = load(a.technique)
    tests = list(enumerate(data["atomic_tests"], 1))
    if a.test_number:
        tests = [t for t in tests if t[0] == a.test_number]
    rc = 0
    for num, test in tests:
        if "linux" not in test["supported_platforms"]:
            print(f"# {a.technique} #{num} '{test['name']}' is Windows-only -> use Invoke-AtomicTest "
                  f"-PathToAtomicsFolder {ATOMICS}")
            continue
        args, command, cleanup = resolve(test, overrides)
        for k, v in args.items():
            if any(h in k.lower() for h in HOST_KEYS):
                check_host(k, v)
        script = cleanup if a.cleanup else command
        print(f"# {a.technique} #{num}: {test['name']}"
              + (" [CLEANUP]" if a.cleanup else "")
              + (" (needs root)" if test["executor"].get("elevation_required") else ""))
        print(script.rstrip() or "# (no cleanup command)")
        if not a.execute or not script.strip():
            continue
        if os.environ.get("DAC_LAB_CONFIRM") != CONFIRM_VALUE:
            sys.exit(f"REFUSED: set DAC_LAB_CONFIRM={CONFIRM_VALUE} to confirm this is an isolated lab host.")
        if test["executor"].get("elevation_required") and os.geteuid() != 0:
            print("# WARNING: test expects root; run with sudo -E for full fidelity")
        shell = "/bin/bash" if test["executor"]["name"] == "bash" else "/bin/sh"
        proc = subprocess.run([shell, "-c", script])
        print(f"# exit code {proc.returncode}")
        rc = rc or proc.returncode
    return rc


if __name__ == "__main__":
    sys.exit(main())
