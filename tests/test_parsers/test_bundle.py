"""Reader of raw bundles v1 (src/aridi/bundle.py)."""

import unittest

from aridi import bundle
from tests.helpers import BOUNDARY, corpus_bundles, make_bundle

META = ("meta.env", "meta.date_utc", "meta.uid", "meta.machine_id", "meta.dbus_machine_id",
        "meta.hostname", "meta.uname")


class CorpusTest(unittest.TestCase):

    def test_corpus_is_present(self):
        self.assertGreaterEqual(len(corpus_bundles()), 33)

    def test_every_corpus_bundle_parses(self):
        for path in corpus_bundles():
            with self.subTest(sample=str(path.parent.relative_to(path.parents[2]))):
                parsed = bundle.read(path)
                self.assertEqual(parsed.format_version, 1)
                for name in META:
                    self.assertIn(name, parsed.sections)
                self.assertEqual(parsed.section("meta.uid").text().strip(), "0")
                self.assertEqual(parsed.section("meta.date_utc").status, "ok")
                self.assertRegex(parsed.section("meta.uname").text(), r"^Linux ")


class SyntheticTest(unittest.TestCase):

    def test_sections_status_rc_and_note(self):
        parsed = bundle.parse(make_bundle([
            ("a.one", b"hello\n"),
            ("a.two", b"", "denied", 1, "cat: x: Permission denied"),
            ("a.three", b"", "missing", "-", "tool not found: foo"),
        ]))
        self.assertEqual(list(parsed.sections), ["a.one", "a.two", "a.three"])
        one, two, three = parsed.sections.values()
        self.assertEqual((one.content, one.status, one.rc, one.size), (b"hello\n", "ok", 0, 6))
        self.assertEqual((two.status, two.rc, two.note),
                         ("denied", 1, "cat: x: Permission denied"))
        self.assertIsNone(three.rc)
        self.assertEqual(one.fields["tool"], "test")

    def test_content_without_final_newline_is_kept_exactly(self):
        parsed = bundle.parse(make_bundle([("a.x", b"no newline")]))
        self.assertEqual(parsed.section("a.x").content, b"no newline")

    def test_binary_and_invalid_utf8_content(self):
        raw = bytes(range(256))
        parsed = bundle.parse(make_bundle([("a.bin", raw)]))
        self.assertEqual(parsed.section("a.bin").content, raw)
        self.assertIn("�", parsed.section("a.bin").text())

    def test_boundary_like_text_inside_content(self):
        other = "f" * 32
        content = (f"--{other} end a.x status=ok rc=0\n"
                   f"--{BOUNDARY} begin a.fake kind=cmd limit=1\n"
                   f"--{BOUNDARY} end a.other status=ok rc=0\n"
                   f"--{BOUNDARY}end a.x status=ok rc=0\n").encode()
        parsed = bundle.parse(make_bundle([("a.x", content), ("a.y", b"after")]))
        self.assertEqual(parsed.section("a.x").content, content)
        self.assertEqual(parsed.section("a.y").content, b"after")
        self.assertNotIn("a.fake", parsed.sections)

    def test_content_over_the_limit_is_cut_and_marked(self):
        data = make_bundle([("a.big", b"x" * 1001)])
        section = bundle.parse(data).section("a.big")
        self.assertTrue(section.truncated)
        self.assertEqual(section.size, 1000)
        exact = bundle.parse(make_bundle([("a.big", b"x" * 1000)])).section("a.big")
        self.assertFalse(exact.truncated)

    def test_missing_section_is_none(self):
        self.assertIsNone(bundle.parse(make_bundle([])).section("meta.uid"))


class InvalidTest(unittest.TestCase):

    def assertInvalid(self, data, error=bundle.BundleError):
        with self.assertRaises(error):
            bundle.parse(data)

    def test_empty(self):
        self.assertInvalid(b"")

    def test_unknown_version(self):
        self.assertInvalid(make_bundle([("a.x", b"1")], version=2), bundle.UnsupportedVersion)

    def test_not_a_bundle(self):
        self.assertInvalid(b"Linux host 6.1 aarch64\n")

    def test_truncated_anywhere(self):
        data = make_bundle([("a.x", b"one\n"), ("a.y", b"two")])
        for cut in range(1, len(data) - 1):
            with self.subTest(cut=cut):
                self.assertInvalid(data[:cut])

    def test_truncated_inside_content_is_truncated_bundle(self):
        data = make_bundle([("a.x", b"one\ntwo\nthree\n")])
        self.assertInvalid(data[:data.index(b"two")], bundle.TruncatedBundle)

    def test_close_count_mismatch(self):
        self.assertInvalid(make_bundle([("a.x", b"1")], close=2))

    def test_no_close_line(self):
        self.assertInvalid(make_bundle([("a.x", b"1")], close=False), bundle.TruncatedBundle)

    def test_data_after_close(self):
        self.assertInvalid(make_bundle([("a.x", b"1")]) + b"extra\n")

    def test_duplicate_section(self):
        self.assertInvalid(make_bundle([("a.x", b"1"), ("a.x", b"2")]))

    def test_unknown_status(self):
        self.assertInvalid(make_bundle([("a.x", b"1", "weird", 0)]))

    def test_invalid_section_name(self):
        self.assertInvalid(make_bundle([("A X", b"1")]))

    def test_short_boundary(self):
        self.assertInvalid(make_bundle([("a.x", b"1")], boundary="abc"))


if __name__ == "__main__":
    unittest.main()
