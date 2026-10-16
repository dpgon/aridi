"""Port names: the table generated from IANA and its builder (TODO.md 7.1)."""

import tempfile
import unittest
from pathlib import Path

from aridi import ports
from tools import build_services

DATA = Path(__file__).resolve().parents[2] / "src" / "aridi" / "data" / "services.csv"

IANA = """Service Name,Port Number,Transport Protocol,Description,Assignee,Contact
ssh,22,tcp,The Secure Shell (SSH) Protocol,,
ssh,22,udp,The Secure Shell (SSH) Protocol,,
,23,tcp,Reserved,,
x11,6000-6063,tcp,X Window System,,
http,80,tcp,World Wide Web HTTP,,
www,80,tcp,World Wide Web HTTP,,
sql*net,66,tcp,"Oracle SQL*NET | with a pipe
and a line break",,
bad name,99,tcp,spaces are not a name,,
imaps,993,tcp,IMAP over TLS,,
"""


class TableTest(unittest.TestCase):

    def test_header_says_source_and_date(self):
        header = [line for line in DATA.read_text(encoding="utf-8").splitlines()
                  if line.startswith("#")]
        self.assertIn("# Port names: name|port|protocol|description", header)
        self.assertTrue(any("iana.org" in line for line in header))
        self.assertTrue(any(line.startswith("# Generated: 20") for line in header))

    def test_every_line_has_four_fields(self):
        for line in DATA.read_text(encoding="utf-8").splitlines():
            if not line.startswith("#"):
                name, port, protocol, _ = line.split("|")
                self.assertTrue(name and port.isdigit())
                self.assertIn(protocol, build_services.PROTOCOLS)

    def test_names_used_by_the_connections(self):
        # The names the corpus connections resolve (TODO.md 3.15), unchanged from 2019.
        for port, protocol, expected in ((22, "tcp", "ssh"), (22, "tcp6", "ssh"),
                                         (67, "udp", "bootps"), (123, "udp", "ntp"),
                                         (53, "udp6", "domain"), (443, "tcp", "https")):
            with self.subTest(port=port, protocol=protocol):
                self.assertEqual(ports.name(port, protocol), expected)

    def test_protocol_matters(self):
        self.assertEqual(ports.name(993, "tcp"), "imaps")
        self.assertIsNone(ports.name(993, "udp"))
        self.assertIsNone(ports.name(65000))


class BuilderTest(unittest.TestCase):

    def test_build(self):
        rows = build_services.build(IANA)
        self.assertEqual([(r[0], r[1], r[2]) for r in rows], [
            ("ssh", 22, "tcp"), ("ssh", 22, "udp"), ("sql*net", 66, "tcp"),
            ("http", 80, "tcp"), ("imaps", 993, "tcp")])
        self.assertEqual(rows[2][3], "Oracle SQL*NET / with a pipe and a line break")

    def test_render_and_refuse_other_files(self):
        text = build_services.render(build_services.build(IANA), "test", "2026-10-16")
        self.assertTrue(text.startswith("# Port names"))
        self.assertIn("http|80|tcp|World Wide Web HTTP\n", text)
        with self.assertRaises(ValueError):
            build_services.build("name,port\nssh,22\n")

    def test_too_few_entries_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            input_file, output = Path(tmp) / "iana.csv", Path(tmp) / "services.csv"
            input_file.write_text(IANA, encoding="utf-8")
            self.assertEqual(build_services.main(["--input", str(input_file),
                                                  "--output", str(output)]), 1)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
