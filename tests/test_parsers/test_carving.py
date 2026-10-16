"""Areas "carving" and "neighbours" (TODO.md 3.16 and 3.17)."""

import ipaddress
import re
import unittest

from aridi import bundle
from aridi.interpret import interpret
from aridi.model import Role, Status
from aridi.parsers import carving, neighbours
from tests.helpers import (CORPUS, corpus_bundles, legacy_bundle, legacy_report, make_bundle,
                           sample_name, samples)


def snapshot_of(path):
    return interpret(bundle.read(path))


def sections(*items):
    return dict(bundle.parse(make_bundle(items)).sections)


class CarvingCorpusTest(unittest.TestCase):

    def test_scenario_addresses_in_every_sample(self):
        for sample in samples():
            with self.subTest(sample=sample_name(sample)):
                section = snapshot_of(sample / "bundle.aridi").sections["carving"]
                self.assertEqual(section.status, Status.OK)
                found = {item["ip"]: item for item in section.data["addresses"]}
                for wanted in ("192.0.2.10", "2001:db8::10", "203.0.113.7", "203.0.113.50",
                               "2001:db8::77", "10.20.30.40", "2001:db8::40"):
                    self.assertIn(wanted, found)
                # A version number, a network, link-local and reserved IPv6 are not hosts.
                for unwanted in ("1.2.3.4", "198.51.100.0", "169.254.10.20", "fe00::",
                                 "ff02::1"):
                    self.assertNotIn(unwanted, found)
                mention = found["192.0.2.10"]["mentions"][0]
                self.assertEqual((mention["path"], mention["line"]),
                                 ("/etc/aridi-corpus.conf", 2))
                names = [n["name"] for n in section.data["names"]]
                self.assertIn("corpus-db.example.internal", names)

    def test_protected_files_are_never_read(self):
        """Only world-readable files of /etc are searched: never shadow or keys."""
        for path in corpus_bundles():
            with self.subTest(bundle=str(path)):
                parsed = bundle.read(path)
                for name in ("carving.etc_ips", "carving.etc_names"):
                    content = parsed.section(name).text()
                    self.assertNotRegex(content, r"(?m)^/etc/g?shadow")
                    self.assertNotRegex(content, r"(?m)^/etc/ssl/private/")

    def test_no_line_text_leaves_the_machine(self):
        for path in corpus_bundles():
            with self.subTest(bundle=str(path)):
                parsed = bundle.read(path)
                for name in ("carving.etc_ips", "carving.log_ips"):
                    for row in parsed.section(name).text().splitlines():
                        self.assertEqual(len(row.split("|")), 7, row)
                        self.assertLess(len(row.split("|", 2)[2]), 80, row)


class CarvingLegacyTest(unittest.TestCase):

    def test_debian12_same_ipv4_in_etc_as_legacy(self):
        report = legacy_report("debian12")
        block = report[report.index("/etc information"):report.index("/var/log information")]
        legacy = set(re.findall(r"\|__(\d+\.\d+\.\d+\.\d+) named in file '/etc", block))
        self.assertEqual(len(legacy), 2)
        data = snapshot_of(legacy_bundle("debian12")).sections["carving"].data
        ours = {item["ip"] for item in data["addresses"]
                if ipaddress.ip_address(item["ip"]).version == 4
                and any(m["source"] == "etc" for m in item["mentions"])}
        self.assertEqual(ours, legacy)


class CarvingSyntheticTest(unittest.TestCase):

    def test_exclusions(self):
        rows = ("/etc/a|1|10.0.0.5||w||\n"          # kept
                "/etc/a|2|10.0.0.6||w||c\n"         # commented
                "/etc/a|3|1.2.3.4||w||v\n"          # version
                "/etc/a|4|10.0.0.0|8|w|s|\n"        # network
                "/etc/a|5|10.0.0.7|32|w|s|\n"       # host prefix: kept
                "/etc/a|6|1.2.3.4||d|p|\n"          # glued: 11.2.3.4.5
                "/etc/a|7|0.1.2.3||w||\n"           # 0.x
                "/etc/a|8|239.1.1.1||w||\n"         # multicast
                "/etc/a|9|fe80::1||w||\n"           # link-local
                "/etc/a|10|2001:db8::5|64|w|s|\n"   # IPv6 network
                "/etc/a|11|1::||d|l|\n"             # "1::sysinit"
                "/etc/a|12|::1||w||\n"              # loopback: kept
                "/etc/a|13|21.48.22.159||w|h|\n"    # "anaconda 21.48.22.159-1"
                "garbage\n")
        result = carving.parse(sections(("carving.etc_ips", rows.encode()),
                                        ("carving.log_ips", b"")))
        self.assertEqual([i["ip"] for i in result.data["addresses"]],
                         ["10.0.0.5", "10.0.0.7", "::1"])
        self.assertEqual(sum(result.data["excluded"].values()), 10)
        self.assertEqual({r.role for r in result.relations}, {Role.NAMED_IN_FILE})
        self.assertEqual(result.relations[0].detail, "/etc/a:1")

    def test_journal_counts(self):
        journal = b"   12 203.0.113.9|||w|\n    3 10.1.1.0|24|w|s|\n"
        result = carving.parse(sections(("carving.etc_ips", b""), ("carving.log_ips", b""),
                                        ("carving.journal_ips", journal)))
        self.assertEqual(result.data["addresses"][0]["mentions"],
                         [{"source": "journal", "path": None, "line": None, "count": 12}])
        self.assertEqual(result.data["counts"]["journal"], 1)

    def test_truncated_search_is_declared(self):
        rows = "".join(f"/etc/a|{n}|10.0.{n // 250}.{n % 250 + 1}||w||\n" for n in range(100))
        result = carving.parse(sections(("carving.etc_ips", rows.encode()),
                                        ("carving.log_ips", b"")))
        self.assertIn("etc addresses", [g.item for g in result.gaps])

    def test_host_names(self):
        self.assertTrue(carving.is_host_name("corpus-db.example.internal"))
        self.assertTrue(carving.is_host_name("ntp1.example.org"))
        self.assertFalse(carving.is_host_name("example.org"))            # one dot, as 2019
        self.assertFalse(carving.is_host_name("org.freedesktop.systemd1"))
        self.assertFalse(carving.is_host_name("50-default.d.conf"))
        self.assertFalse(carving.is_host_name("libc.so.6"))


class NeighboursTest(unittest.TestCase):

    def test_every_sample(self):
        for sample in samples():
            with self.subTest(sample=sample_name(sample)):
                section = snapshot_of(sample / "bundle.aridi").sections["neighbours"]
                self.assertEqual(section.status, Status.OK)
                self.assertTrue(section.volatile)

    def test_vms_see_their_gateway(self):
        for name in ("vm-debian12-arm64", "vm-rocky9-arm64", "vm-debian12-amd64"):
            with self.subTest(sample=name):
                snapshot = snapshot_of(CORPUS / name / "vm" / "bundle.aridi")
                self.assertTrue(snapshot.sections["neighbours"].data["neighbours"])
                self.assertTrue([r for r in snapshot.relations if r.role == Role.NEIGHBOUR])

    def test_container_without_ip_uses_proc_arp(self):
        # Debian minimal has no iproute2 (Alpine has "ip" in busybox).
        data = snapshot_of(CORPUS / "debian12" / "minimal" / "bundle.aridi").sections[
            "neighbours"].data
        self.assertEqual(data["source"], "/proc/net/arp (IPv4 only)")

    def test_synthetic_tables(self):
        arp = ("IP address       HW type     Flags       HW address            Mask     Device\n"
               "192.168.5.2      0x1         0x2         52:55:55:12:34:56     *        eth0\n"
               "192.168.5.9      0x1         0x0         00:00:00:00:00:00     *        eth0\n")
        found = neighbours.parse_proc_arp(arp)
        self.assertEqual([(n["ip"], n["state"]) for n in found],
                         [("192.168.5.2", "complete"), ("192.168.5.9", "incomplete")])
        neigh = ("192.168.5.2 dev eth0 lladdr 52:55:55:12:34:56 REACHABLE\n"
                 "fe80::2 dev eth0 lladdr 52:55:55:12:34:57 router STALE\n"
                 "192.168.5.7 dev eth0 FAILED\n")
        result = neighbours.parse(sections(("neighbours.ip_neigh", neigh.encode())))
        self.assertEqual([str(r.ip) for r in result.relations], ["192.168.5.2", "fe80::2"])
        self.assertTrue(result.data["neighbours"][1]["router"])


if __name__ == "__main__":
    unittest.main()
