"""Text report (src/aridi/views/text.py).

The golden file is the detailed report of tests/corpus/debian12/minimal. It changes when
the corpus is captured again or the report changes; regenerate it with
"tests/run.sh golden" and review the diff.
"""

import unittest

from aridi import bundle
from aridi.interpret import AREAS, AreaResult, interpret
from aridi.views import text
from tests.helpers import CORPUS, REPO, make_bundle

GOLDEN_SAMPLE = CORPUS / "debian12" / "minimal" / "bundle.aridi"
GOLDEN = REPO / "tests" / "test_core" / "data" / "report-debian12-minimal.txt"


class TextTest(unittest.TestCase):

    def test_golden_corpus_report(self):
        report = text.render(interpret(bundle.read(GOLDEN_SAMPLE)), detail=True)
        self.assertEqual(report, GOLDEN.read_text(encoding="utf-8"))

    def test_every_area_and_the_gaps_section(self):
        snapshot = interpret(bundle.read(GOLDEN_SAMPLE))
        report = text.render(snapshot)
        for area in AREAS:
            self.assertIn(area.title, report)
        gaps = report.split("What could not be seen\n")[1]
        without_parser = [name for name, s in snapshot.sections.items()
                          if s.status == "no_parser"]
        self.assertEqual(gaps.count("no_parser"), len(without_parser))
        result = "with gaps" if snapshot.gaps() else "complete"
        self.assertIn(f"Result:       {result}", report)

    def test_untrusted_text_is_escaped(self):
        hostname = b"evil\x1b[31mred\x07\n"
        snapshot = interpret(bundle.parse(make_bundle([("meta.hostname", hostname)])),
                             parsers={})
        report = text.render(snapshot)
        self.assertNotIn("\x1b", report)
        self.assertNotIn("\x07", report)
        self.assertIn("evil\\x1b[31mred\\x07", report)

    def test_clean(self):
        self.assertEqual(text.clean("a\tb\nc\x9bd"), "a\\tb\\nc\\x9bd")
        self.assertEqual(text.clean(None), "")
        self.assertEqual(text.clean("ñandú"), "ñandú")

    def test_human_duration(self):
        self.assertEqual(text.human_duration(247016), "2 days, 20:36:56")
        self.assertEqual(text.human_duration(86400 + 59), "1 day, 00:00:59")
        self.assertEqual(text.human_duration(3599.9), "00:59:59")

    def test_renderer_used_for_ok_areas(self):
        parsed = bundle.parse(make_bundle([("system.os_release", b"ID=debian\n")]))
        snapshot = interpret(parsed, parsers={"system": lambda s: AreaResult({"id": "x"})})
        original = text._renderers.pop("system", None)
        try:
            report = text.render(snapshot)
            self.assertIn("(no text view for this area yet)", report)
            text.renderer("system")(lambda data, detail: [f"Id: {data['id']}\x1b"])
            report = text.render(snapshot)
        finally:
            text._renderers.pop("system", None)
            if original:
                text._renderers["system"] = original
        self.assertIn("  Id: x\\x1b", report)


if __name__ == "__main__":
    unittest.main()
