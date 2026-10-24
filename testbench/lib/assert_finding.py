#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Exits 0 if hunter's JSON report (at argv[1]) contains a finding from
`check` (argv[2]) whose summary or detail contains `substr` (argv[3]);
exits 1 otherwise. Used by testbench scenarios to assert a planted
technique was actually detected.
"""
import json
import sys


def main() -> int:
    if len(sys.argv) != 4:
        print(f"usage: {sys.argv[0]} <json-report-path> <check-name> <substring>", file=sys.stderr)
        return 2

    path, check, substr = sys.argv[1], sys.argv[2], sys.argv[3]
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    for finding in data.get("findings", []):
        if finding.get("check") == check and (substr in finding.get("summary", "") or substr in finding.get("detail", "")):
            return 0

    print(f"no '{check}' finding containing {substr!r} in {path}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
