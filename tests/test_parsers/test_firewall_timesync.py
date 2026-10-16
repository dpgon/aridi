"""Areas "firewall" and "timesync" (TODO.md 3.10 and 3.11)."""

import unittest

from aridi import bundle
from aridi.interpret import interpret
from aridi.model import Role, Status
from aridi.parsers import firewall, timesync
from tests.helpers import CORPUS, make_bundle

VMS = ("vm-debian12-arm64", "vm-rocky9-arm64", "vm-debian12-amd64")


def snapshot_of(name, variant):
    return interpret(bundle.read(CORPUS / name / variant / "bundle.aridi"))


def relations(snapshot, role):
    return {str(r.ip) for r in snapshot.relations if r.role == role}


class FirewallCorpusTest(unittest.TestCase):

    def test_scenario_nftables_rules_in_the_vms(self):
        for name in VMS:
            with self.subTest(sample=name):
                snapshot = snapshot_of(name, "vm")
                section = snapshot.sections["firewall"]
                self.assertEqual(section.status, Status.OK)
                self.assertIn("nftables", section.data["engines"])
                self.assertTrue({"192.0.2.10", "2001:db8::10"} <=
                                relations(snapshot, Role.FW_ALLOWED_IN))
                self.assertIn("198.51.100.5", relations(snapshot, Role.FW_ALLOWED_OUT))
                forward = [c for c in section.data["chains"]
                           if c["table"] == "aridi_corpus" and c["hook"] == "forward"]
                self.assertEqual([c["policy"] for c in forward], ["drop"])
                self.assertIn({"engine": "nftables", "family": "inet", "table": "aridi_corpus",
                               "chain": "forward", "direction": "forward", "action": "accept",
                               "source": "10.0.0.0/8", "destination": None, "protocol": None,
                               "port": None}, section.data["rules"])

    def test_firewalld_in_rocky9(self):
        snapshot = snapshot_of("vm-rocky9-arm64", "vm")
        data = snapshot.sections["firewall"].data
        self.assertIn("firewalld", data["engines"])
        self.assertIn("192.0.2.20", relations(snapshot, Role.FW_ALLOWED_IN))
        self.assertTrue(any(z["active"] for z in data["firewalld_zones"]))

    def test_container_without_cap_net_admin_says_why(self):
        section = snapshot_of("debian12", "server").sections["firewall"]
        nft_gap = [g for g in section.gaps if g.item == "nft_json"]
        self.assertEqual([g.status for g in nft_gap], [Status.DENIED])
        self.assertIn("Operation not permitted", nft_gap[0].reason)


class FirewallSyntheticTest(unittest.TestCase):

    def test_iptables_save(self):
        save = ("*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n"
                "-A INPUT -s 192.0.2.7/32 -p tcp -m tcp --dport 22 -j ACCEPT\n"
                "-A INPUT -s 10.0.0.0/8 -j ACCEPT\n"
                "-A OUTPUT -d 198.51.100.9/32 -p udp -m udp --dport 53 -j ACCEPT\nCOMMIT\n")
        result = firewall.parse(dict(bundle.parse(make_bundle(
            [("firewall.iptables_legacy", save.encode())])).sections))
        policies = {c["name"]: c["policy"] for c in result.data["chains"]}
        self.assertEqual(policies, {"INPUT": "drop", "FORWARD": "drop", "OUTPUT": "accept"})
        self.assertEqual({(str(r.ip), r.role) for r in result.relations},
                         {("192.0.2.7", Role.FW_ALLOWED_IN), ("198.51.100.9", Role.FW_ALLOWED_OUT)})

    def test_ufw(self):
        status = ("Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing)"
                  "\n\nTo                         Action      From\n--                         "
                  "------      ----\n22/tcp                     ALLOW IN    192.0.2.8\n")
        ufw = firewall.parse_ufw(status)
        self.assertTrue(ufw["active"])
        self.assertEqual(ufw["rules"], [["22/tcp", "ALLOW IN", "192.0.2.8"]])

    def test_broken_nft_json_is_a_gap(self):
        result = firewall.parse(dict(bundle.parse(make_bundle(
            [("firewall.nft_json", b"{not json")])).sections))
        self.assertEqual([g.item for g in result.gaps], ["nftables"])

    def test_single_address(self):
        self.assertEqual(str(firewall._single_address("192.0.2.1/32")), "192.0.2.1")
        self.assertEqual(str(firewall._single_address("2001:db8::1/128")), "2001:db8::1")
        self.assertIsNone(firewall._single_address("10.0.0.0/8"))
        self.assertIsNone(firewall._single_address("1.2.3.4,5.6.7.8"))


class TimesyncTest(unittest.TestCase):

    def test_chrony_in_rocky9(self):
        snapshot = snapshot_of("vm-rocky9-arm64", "vm")
        data = snapshot.sections["timesync"].data
        self.assertIn("chrony", data["services"])
        self.assertIn("192.0.2.124", [c["server"] for c in data["configured"]])
        self.assertIn("192.0.2.124", relations(snapshot, Role.NTP_SERVER))

    def test_timesyncd_in_debian(self):
        for name in ("vm-debian12-arm64", "vm-debian12-amd64"):
            with self.subTest(sample=name):
                snapshot = snapshot_of(name, "vm")
                data = snapshot.sections["timesync"].data
                self.assertIn("systemd-timesyncd", data["services"])
                servers = [c["server"] for c in data["configured"] if c["kind"] == "server"]
                self.assertEqual(servers, ["ntp1.example.org", "192.0.2.123"])
                # Names stay text: only the IP literal is a relation.
                self.assertEqual(relations(snapshot, Role.NTP_SERVER), {"192.0.2.123"})

    def test_container_without_time_service(self):
        section = snapshot_of("debian12", "minimal").sections["timesync"]
        self.assertEqual(section.status, Status.OK)
        self.assertEqual([(g.item, g.status) for g in section.gaps],
                         [("time service", Status.NA)])

    def test_timesyncd_drop_in_overrides(self):
        values = timesync.parse_timesyncd(
            "==> /etc/systemd/timesyncd.conf <==\n[Time]\n#NTP=\nNTP=a.example\n"
            "==> /etc/systemd/timesyncd.conf.d/x.conf <==\n[Time]\nNTP=b.example 192.0.2.1\n")
        self.assertEqual(values["NTP"], ["b.example", "192.0.2.1"])

    def test_chronyc_and_ntpq_sources(self):
        chronyc = ("MS Name/IP address         Stratum Poll Reach LastRx Last sample\n"
                   "====================================\n"
                   "^* 192.0.2.124                   2   6   377    12   +10us[ +12us] +/- 20ms\n"
                   "^? 192.0.2.125                   0   6     0     -     +0ns[   +0ns] "
                   "+/-  0ns\n")
        ntpq = ("     remote           refid      st t when poll reach   delay   offset  jitter\n"
                "==============================================================================\n"
                "*192.0.2.1      .GPS.            1 u   10   64  377    0.5    0.01   0.002\n")
        result = timesync.parse(dict(bundle.parse(make_bundle(
            [("timesync.chronyc", chronyc.encode()), ("timesync.ntpq", ntpq.encode())])).sections))
        self.assertEqual([(i["server"], i["selected"]) for i in result.data["in_use"]],
                         [("192.0.2.124", True), ("192.0.2.125", False), ("192.0.2.1", True)])


if __name__ == "__main__":
    unittest.main()
