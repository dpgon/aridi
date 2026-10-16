"""Command line interface (src/aridi/cli.py): subcommands and exit codes."""

import io
import json
import os
import shutil
import stat
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from aridi import bundle as bundle_module
from aridi import cli
from aridi.interpret import interpret
from aridi.model import Outcome
from tests.helpers import CORPUS, make_bundle

SAMPLE = CORPUS / "debian12" / "minimal" / "bundle.aridi"
# The expected exit code comes from the snapshot itself (complete since phase 3).
EXPECTED = (cli.EXIT_COMPLETE if interpret(bundle_module.read(SAMPLE)).outcome()
            == Outcome.COMPLETE else cli.EXIT_GAPS)


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main([str(a) for a in argv])
    return code, out.getvalue(), err.getvalue()


class CliTest(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)

    def write(self, name, data):
        path = self.tmp / name
        path.write_bytes(data)
        return path

    def test_validate_corpus_sample(self):
        code, out, _ = run("validate", SAMPLE)
        self.assertEqual(code, cli.EXIT_COMPLETE)
        self.assertIn("valid bundle format 1", out)

    def test_invalid_and_unreadable_bundles(self):
        cases = {
            "empty": self.write("empty.aridi", b""),
            "truncated": self.write("t.aridi", SAMPLE.read_bytes()[:200]),
            "version": self.write("v.aridi", make_bundle([], version=9)),
            "missing": self.tmp / "does-not-exist.aridi",
        }
        for command in ("validate", "interpret", "report"):
            for case, path in cases.items():
                with self.subTest(command=command, case=case):
                    code, out, err = run(command, path)
                    self.assertEqual(code, cli.EXIT_FAILED)
                    self.assertEqual(out, "")
                    self.assertIn("aridi: ERROR:", err)

    def test_interpret_to_stdout(self):
        code, out, _ = run("interpret", SAMPLE)
        self.assertEqual(code, EXPECTED)
        data = json.loads(out)
        self.assertEqual(data["schema_version"], 1)
        self.assertEqual(len(data["sections"]), 17)

    def test_interpret_to_new_file_0600(self):
        target = self.tmp / "snapshot.json"
        code, out, _ = run("interpret", SAMPLE, "-o", target)
        self.assertEqual((code, out), (EXPECTED, ""))
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        self.assertEqual(json.loads(target.read_text())["schema_version"], 1)

    def test_interpret_never_overwrites_nor_follows_symlinks(self):
        existing = self.write("existing.json", b"keep")
        victim = self.write("victim", b"keep")
        link = self.tmp / "link.json"
        os.symlink(victim, link)
        dangling = self.tmp / "dangling.json"
        os.symlink(self.tmp / "nowhere", dangling)
        for target in (existing, link, dangling):
            with self.subTest(target=target.name):
                code, _, err = run("interpret", SAMPLE, "-o", target)
                self.assertEqual(code, cli.EXIT_FAILED)
                self.assertIn("cannot create", err)
        self.assertEqual(victim.read_bytes(), b"keep")
        self.assertEqual(existing.read_bytes(), b"keep")
        self.assertFalse((self.tmp / "nowhere").exists())

    def test_report_summary_and_detail(self):
        code, out, _ = run("report", SAMPLE)
        self.assertEqual(code, EXPECTED)
        self.assertIn("Level:        summary", out)
        code, out, _ = run("report", SAMPLE, "--detail")
        self.assertIn("Level:        detail", out)

    def test_complete_exit_code(self):
        bundle = make_bundle([])
        path = self.write("b.aridi", bundle)
        original = cli.interpret

        def all_ok(parsed):
            snapshot = original(parsed, parsers={})
            for section in snapshot.sections.values():
                section.status, section.data, section.gaps = "ok", {}, []
            return snapshot

        cli.interpret = all_ok
        try:
            code, _, _ = run("report", path)
        finally:
            cli.interpret = original
        self.assertEqual(code, cli.EXIT_COMPLETE)

    def test_verbose_logging(self):
        bad = self.write("bad.aridi", b"ARIDI-BUNDLE 1 x\nboundary " + b"a" * 32 + b"\n")
        self.assertIn("ERROR", run("-v", "validate", bad)[2])


if __name__ == "__main__":
    unittest.main()
