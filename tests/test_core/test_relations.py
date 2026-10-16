"""Relation map and global checks of phase 3 (TODO.md 3.18)."""

import ipaddress
import unittest

from aridi import bundle
from aridi.interpret import interpret
from aridi.model import Relation, Role, Status
from aridi.relations import consolidate
from aridi.views import text
from tests.helpers import CORPUS, legacy_bundle, sample_name, samples

# Roles that the corpus cannot produce, and where they are tested instead.
SYNTHETIC_ONLY = {
    Role.FAILED_LOGIN_SOURCE: "test_volatile (the failed logins of the corpus are loopback)",
    Role.SCAN_OPEN_PORT: "phase 7 (scanner of the central component)",
}


class RelationsTest(unittest.TestCase):

    def test_every_role_comes_from_a_sample_or_is_tested_elsewhere(self):
        seen = set()
        for sample in samples():
            seen |= {r.role for r in interpret(bundle.read(sample / "bundle.aridi")).relations}
        self.assertEqual(set(Role) - seen, set(SYNTHETIC_ONLY))

    def test_v4_and_v6_sorted_together_local_first(self):
        relations = [Relation("2001:db8::1", Role.NAMED_IN_FILE, "carving"),
                     Relation("192.0.2.1", Role.DNS_SERVER, "network"),
                     Relation("::1", Role.LOCAL, "network"),
                     Relation("127.0.0.1", Role.LOCAL, "network"),
                     Relation("192.0.2.1", Role.NAMED_IN_FILE, "carving", "/etc/x:1"),
                     Relation("192.0.2.1", Role.DNS_SERVER, "network")]
        nodes = consolidate(relations)
        self.assertEqual([str(n.ip) for n in nodes],
                         ["127.0.0.1", "::1", "192.0.2.1", "2001:db8::1"])
        self.assertEqual([n.local for n in nodes], [True, True, False, False])
        self.assertEqual(len(nodes[2].roles), 2)

    def test_infrastructure_view_like_legacy_oi(self):
        report = text.render(interpret(bundle.read(legacy_bundle("debian12"))))
        block = report.split("Infrastructure\n")[1].split("What could not be seen")[0]
        self.assertIn("Local machine:\n  127.0.0.1", block)
        self.assertIn("Remote addresses:\n  192.168.65.7\n    dns_server (network", block)

    def test_corpus_map_has_v4_and_v6(self):
        snapshot = interpret(bundle.read(CORPUS / "debian12" / "bridge" / "bundle.aridi"))
        versions = {node.ip.version for node in consolidate(snapshot.relations)}
        self.assertEqual(versions, {4, 6})
        self.assertTrue(all(isinstance(node.ip, (ipaddress.IPv4Address, ipaddress.IPv6Address))
                            for node in consolidate(snapshot.relations)))


class GlobalRegressionTest(unittest.TestCase):

    def test_no_area_in_error_in_any_sample(self):
        """TODO.md 3.18: any "error" is a bug or a misclassified na/missing/denied."""
        for sample in samples():
            with self.subTest(sample=sample_name(sample)):
                snapshot = interpret(bundle.read(sample / "bundle.aridi"))
                errors = [(name, item, reason) for name, item, status, reason in snapshot.gaps()
                          if status == Status.ERROR]
                self.assertEqual(errors, [])
                self.assertEqual([n for n, s in snapshot.sections.items()
                                  if s.status == Status.NO_PARSER], [])


if __name__ == "__main__":
    unittest.main()
