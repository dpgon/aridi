"""Checks the bundles written by tests/collector/test_script.sh with the core reader.

Usage: python tests/collector/check_bundles.py DIR

  NAME.root.SHELL.aridi  full run as root: valid, meta sections ok, uid 0
  NAME.nobody.aridi      full run as uid 65534: valid, uid 65534
  NAME.probe.aridi       section functions on cases with a known status
"""

import sys
from pathlib import Path

from aridi import bundle

PROBE = {
    "t.stdin": ("ok", 0),
    "t.shadow_file": ("denied", None),
    "t.shadow_cmd": ("denied", 1),
    "t.slow": ("timeout", None),
    "t.nosuch": ("missing", None),
    "t.nofile": ("na", None),
    "t.big": ("ok", None),
    "t.fail": ("error", 3),
    "t.text": ("ok", 0),
}


def check_full(parsed, uid):
    problems = []
    for name in ("meta.env", "meta.date_utc", "meta.uid", "meta.hostname", "meta.uname"):
        section = parsed.section(name)
        if section is None or section.status != "ok":
            problems.append(f"{name}: {section and section.status}")
    if parsed.section("meta.uid") and parsed.section("meta.uid").text().strip() != uid:
        problems.append(f"meta.uid is not {uid}")
    if "boundary_source=urandom" not in parsed.section("meta.env").text():
        problems.append("weak boundary")
    return problems


def check_probe(parsed):
    problems = []
    for name, (status, rc) in PROBE.items():
        section = parsed.section(name)
        if section is None:
            problems.append(f"{name}: absent")
            continue
        if section.status != status or (rc is not None and section.rc != rc):
            problems.append(f"{name}: {section.status} rc={section.rc}, expected {status}")
    big = parsed.section("t.big")
    if big and not (big.truncated and big.size == 1000):
        problems.append(f"t.big: truncated={big.truncated} size={big.size}")
    fail = parsed.section("t.fail")
    if fail and (fail.text() != "partial\n" or not fail.note.startswith("boom?")):
        problems.append(f"t.fail: content {fail.content!r} note {fail.note!r}")
    if parsed.section("t.stdin") and parsed.section("t.stdin").content:
        problems.append("t.stdin: a section command read stdin")
    if parsed.section("t.text") and parsed.section("t.text").text() != "computed value\n":
        problems.append("t.text content")
    return problems


def main(directory):
    paths = sorted(Path(directory).glob("*.aridi"))
    if not paths:
        print("check_bundles: no bundles")
        return 1
    failures = 0
    for path in paths:
        try:
            parsed = bundle.read(path)
        except bundle.BundleError as exc:
            problems = [f"invalid bundle: {exc}"]
        else:
            if ".probe." in path.name:
                problems = check_probe(parsed)
            else:
                problems = check_full(parsed, "65534" if ".nobody." in path.name else "0")
        if problems:
            failures += 1
            print(f"FAIL {path.name}: {'; '.join(problems)}")
        else:
            print(f"ok {path.name}: {len(parsed.sections)} sections")
    print(f"check_bundles: {len(paths)} bundles, {failures} failing")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
