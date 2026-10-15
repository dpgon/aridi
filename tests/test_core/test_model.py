"""Snapshot model v1 (src/aridi/model.py)."""

import ipaddress
import json
import unittest

from aridi.model import (SCHEMA_VERSION, Machine, Outcome, Relation, Role, Section,
                         Snapshot, SnapshotError, Status)


def sample():
    return Snapshot(
        machine=Machine("0" * 32, "host1"),
        collected_at="2026-10-15T10:00:00Z",
        collector_version="2.0.0.test",
        bundle_format=1,
        sections={
            "system": Section(Status.OK, None, {"id": "debian", "version_id": "12"}),
            "processes": Section(Status.NO_PARSER, "no analyzer", volatile=True),
        },
        relations=[
            Relation("192.0.2.10", Role.DNS_SERVER, "network"),
            Relation("2001:db8::40", "named_in_file", "carving", "/etc/hosts:3"),
        ],
    )


class ModelTest(unittest.TestCase):

    def test_json_round_trip(self):
        snapshot = sample()
        again = Snapshot.from_json(snapshot.to_json())
        self.assertEqual(again, snapshot)
        self.assertEqual(again.to_dict(), snapshot.to_dict())

    def test_json_fields(self):
        data = json.loads(sample().to_json())
        self.assertEqual(data["schema_version"], SCHEMA_VERSION)
        self.assertEqual(data["machine"], {"machine_id": "0" * 32, "hostname": "host1"})
        self.assertEqual(data["sections"]["processes"],
                         {"status": "no_parser", "reason": "no analyzer", "data": None,
                          "volatile": True})
        self.assertEqual(data["relations"][1], {"ip": "2001:db8::40", "role": "named_in_file",
                                                "source": "carving",
                                                "detail": "/etc/hosts:3"})
        self.assertEqual(data["outcome"], "gaps")

    def test_ip_v4_and_v6(self):
        v4, v6 = sample().relations
        self.assertIsInstance(v4.ip, ipaddress.IPv4Address)
        self.assertIsInstance(v6.ip, ipaddress.IPv6Address)

    def test_unknown_role_rejected(self):
        with self.assertRaises(SnapshotError):
            Relation("192.0.2.1", "Remote machine", "network")
        data = json.loads(sample().to_json())
        data["relations"][0]["role"] = "dns server"
        with self.assertRaises(SnapshotError):
            Snapshot.from_dict(data)

    def test_invalid_ip_rejected(self):
        with self.assertRaises(SnapshotError):
            Relation("1.2.3.4.5", Role.LOCAL, "carving")

    def test_unknown_status_rejected(self):
        with self.assertRaises(SnapshotError):
            Section("fine")

    def test_unknown_schema_version_rejected(self):
        data = json.loads(sample().to_json())
        for version in (0, 2, None, "1"):
            data["schema_version"] = version
            with self.subTest(version=version), self.assertRaises(SnapshotError):
                Snapshot.from_dict(data)

    def test_malformed_json(self):
        for text in ("", "[]", "{", '{"schema_version": 1}'):
            with self.subTest(text=text), self.assertRaises(SnapshotError):
                Snapshot.from_json(text)

    def test_outcome(self):
        snapshot = sample()
        self.assertEqual(snapshot.outcome(), Outcome.GAPS)
        self.assertEqual([name for name, _ in snapshot.gaps()], ["processes"])
        snapshot.sections["processes"] = Section(Status.OK, data=[], volatile=True)
        self.assertEqual(snapshot.outcome(), Outcome.COMPLETE)


if __name__ == "__main__":
    unittest.main()
