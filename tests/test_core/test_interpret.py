"""From bundle to snapshot (src/aridi/interpret.py)."""

import logging
import unittest

from aridi import bundle
from aridi.interpret import AREA_NAMES, AREAS, AreaResult, interpret, register
from aridi.model import Relation, Role, Status
from tests.helpers import corpus_bundles, make_bundle

MACHINE_ID = "4c4c4544004d3510804ab4c04f4e3332"


def synthetic(*extra):
    return bundle.parse(make_bundle([
        ("meta.date_utc", b"2026-10-15T10:00:00Z\n"),
        ("meta.machine_id", MACHINE_ID.encode() + b"\n"),
        ("meta.hostname", b"host1\n"),
        *extra,
    ]))


class InterpretTest(unittest.TestCase):

    def test_seventeen_areas_in_2019_order(self):
        self.assertEqual(len(AREAS), 17)
        self.assertEqual(AREA_NAMES[0], "system")
        self.assertEqual(AREA_NAMES[-1], "neighbours")

    def test_header_from_meta_sections(self):
        snapshot = interpret(synthetic(), parsers={})
        self.assertEqual(snapshot.machine.machine_id, MACHINE_ID)
        self.assertEqual(snapshot.machine.hostname, "host1")
        self.assertEqual(snapshot.collected_at, "2026-10-15T10:00:00Z")
        self.assertEqual(snapshot.collector_version, "2.0.0.test")

    def test_dbus_machine_id_fallback_and_malformed_ids(self):
        parsed = bundle.parse(make_bundle([
            ("meta.machine_id", b"", "na", "-", "not found: /etc/machine-id"),
            ("meta.dbus_machine_id", MACHINE_ID.encode() + b"\n"),
        ]))
        self.assertEqual(interpret(parsed, parsers={}).machine.machine_id, MACHINE_ID)
        parsed = bundle.parse(make_bundle([("meta.machine_id", b"uninitialized\n"),
                                           ("meta.date_utc", b"yesterday\n")]))
        with self.assertLogs("aridi.interpret", logging.WARNING):
            snapshot = interpret(parsed, parsers={})
        self.assertIsNone(snapshot.machine.machine_id)
        self.assertIsNone(snapshot.collected_at)

    def test_every_area_present_without_parsers(self):
        snapshot = interpret(synthetic(), parsers={})
        self.assertEqual(list(snapshot.sections), list(AREA_NAMES))
        for name, section in snapshot.sections.items():
            self.assertEqual(section.status, Status.NO_PARSER, name)
            self.assertTrue(section.reason)
        self.assertTrue(snapshot.sections["processes"].volatile)
        self.assertFalse(snapshot.sections["system"].volatile)

    def test_area_without_sections_is_not_collected(self):
        snapshot = interpret(synthetic(), parsers={"system": lambda s: AreaResult({})})
        self.assertEqual(snapshot.sections["system"].status, Status.NOT_COLLECTED)

    def test_parser_receives_its_sections_and_returns_relations(self):
        seen = {}

        def system(sections):
            seen.update(sections)
            return AreaResult({"id": "debian"},
                              [Relation("192.0.2.53", Role.DNS_SERVER, "system")])

        snapshot = interpret(synthetic(("system.os_release", b"ID=debian\n"),
                                       ("hardware.cpuinfo", b"x")),
                             parsers={"system": system})
        self.assertEqual(list(seen), ["system.os_release"])
        self.assertEqual(snapshot.sections["system"].status, Status.OK)
        self.assertEqual(snapshot.sections["system"].data, {"id": "debian"})
        self.assertEqual([str(r.ip) for r in snapshot.relations], ["192.0.2.53"])

    def test_failing_parser_does_not_take_others_down(self):
        def broken(sections):
            raise KeyError("ID")

        parsers = {"system": broken, "hardware": lambda s: AreaResult({"cpus": 4})}
        parsed = synthetic(("system.os_release", b""), ("hardware.cpuinfo", b""))
        with self.assertLogs("aridi.interpret", logging.ERROR):
            snapshot = interpret(parsed, parsers=parsers)
        self.assertEqual(snapshot.sections["system"].status, Status.ERROR)
        self.assertIn("KeyError", snapshot.sections["system"].reason)
        self.assertEqual(snapshot.sections["hardware"].status, Status.OK)
        self.assertEqual(snapshot.sections["packages"].status, Status.NO_PARSER)

    def test_parser_may_declare_a_gap(self):
        parsers = {"system": lambda s: AreaResult(None, status=Status.DENIED,
                                                  reason="cannot read /etc/os-release")}
        snapshot = interpret(synthetic(("system.os_release", b"")), parsers=parsers)
        self.assertEqual(snapshot.sections["system"].status, Status.DENIED)

    def test_register_rejects_unknown_area(self):
        with self.assertRaises(ValueError):
            register("printers")

    def test_corpus_bundles_interpret_with_registry(self):
        for path in corpus_bundles():
            with self.subTest(sample=str(path.parent)):
                snapshot = interpret(bundle.read(path))
                self.assertEqual(len(snapshot.sections), 17)
                self.assertRegex(snapshot.collected_at, r"^\d{4}-")
                self.assertTrue(snapshot.machine.hostname)


if __name__ == "__main__":
    unittest.main()
