"""Fail only for a dependency advisory that has a fixed version.

pip-audit exits non-zero for any known vulnerability. An advisory with no fix yet cannot be acted on, so it is
printed and the build passes; one with a fix means uv.lock should move to the fixed version. Usage:
audit_gate.py audit.json (the output of pip-audit --format json)."""
from __future__ import annotations

import json
import sys


def main(path: str) -> int:
    fixable, unfixed = [], []
    for dep in json.load(open(path))["dependencies"]:
        for vuln in dep.get("vulns", []):
            fixed_in = ", ".join(vuln["fix_versions"]) or "no release yet"
            line = f"{dep['name']} {dep['version']}: {vuln['id']} (fixed in {fixed_in})"
            (fixable if vuln["fix_versions"] else unfixed).append(line)
    for line in sorted(set(unfixed)):
        print(f"no fix available, not failing: {line}")
    for line in sorted(set(fixable)):
        print(f"fix available, update uv.lock: {line}")
    return 1 if fixable else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
