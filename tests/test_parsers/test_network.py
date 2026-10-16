"""Area "network" (src/aridi/parsers/network.py), TODO.md 3.9."""

import ipaddress
import re
import unittest

from aridi import bundle
from aridi.interpret import interpret
from aridi.model import Role, Status
from aridi.parsers import network
from tests.helpers import (CORPUS, facts, legacy_bundle, make_bundle, sample_name, samples)


def snapshot_of(path):
    return interpret(bundle.read(path))


def parse(*sections):
    return network.parse(dict(bundle.parse(make_bundle(sections)).sections))


def listening(data):
    return {(s["proto"], s["address"], s["port"]) for s in data["listening"]}


class CorpusTest(unittest.TestCase):

    def test_area_ok_everywhere(self):
        for sample in samples():
            with self.subTest(sample=sample_name(sample)):
                section = snapshot_of(sample / "bundle.aridi").sections["network"]
                self.assertEqual(section.status, Status.OK)
                self.assertEqual(section.gaps, [])
                self.assertTrue(section.data["interfaces"])

    def test_bridge_eth0_at_ifn(self):
        """docs/MVP.md n.º 15: "eth0@ifN" names broke the area in 2019."""
        for sample in samples():
            if sample.name != "bridge":
                continue
            with self.subTest(sample=sample_name(sample)):
                data = snapshot_of(sample / "bundle.aridi").sections["network"].data
                eth0 = next(i for i in data["interfaces"] if i["name"] == "eth0")
                self.assertRegex(eth0["peer"] or "", r"^if\d+$")
                self.assertTrue(any(a["version"] == 4 for a in eth0["addresses"]))
                self.assertTrue(eth0["mac"])

    def test_scenario_listeners_tcp6_udp_and_local(self):
        """docs/MVP.md n.º 16: IPv6 and UDP listeners were missing in 2019."""
        for sample in samples():
            scenario = (sample / "scenario.txt").read_text()
            with self.subTest(sample=sample_name(sample)):
                found = listening(snapshot_of(sample / "bundle.aridi").sections["network"].data)
                if "ok listener tcp6-any 8080" in scenario:
                    self.assertIn(("tcp6", "::", 8080), found)
                if "ok listener tcp4-local 8081" in scenario:
                    self.assertIn(("tcp", "127.0.0.1", 8081), found)
                if "ok listener udp4-any 5514" in scenario:
                    self.assertIn(("udp", "0.0.0.0", 5514), found)

    def test_listener_process_is_known(self):
        data = snapshot_of(CORPUS / "debian12" / "server" / "bundle.aridi").sections[
            "network"].data
        sock = next(s for s in data["listening"] if s["port"] == 8080)
        self.assertEqual([p["name"] for p in sock["processes"]], ["socat"])

    def test_same_ports_as_ss(self):
        for sample in samples():
            ss = facts(sample).get("listening", "")
            if ss.startswith("(missing") or not ss.strip():
                continue
            with self.subTest(sample=sample_name(sample)):
                expected = set()
                for line in ss.splitlines()[1:]:
                    fields = line.split()
                    if len(fields) >= 5 and fields[0] in ("tcp", "udp"):
                        expected.add((fields[0], int(fields[4].rsplit(":", 1)[1])))
                data = snapshot_of(sample / "bundle.aridi").sections["network"].data
                # Unconnected UDP sockets on ephemeral ports (>= 32768, e.g. a DNS query in
                # flight) come and go between the collector and facts.sh.
                got = {(s["proto"].rstrip("6"), s["port"]) for s in data["listening"]
                       if not s["proto"].startswith("raw")}
                self.assertEqual({p for p in got if p[1] < 32768},
                                 {p for p in expected if p[1] < 32768})

    def test_ipv6_dns_server_is_not_null(self):
        """docs/ESTUDIO.md §8: an IPv6 nameserver became a null IP in 2019."""
        snapshot = snapshot_of(CORPUS / "debian12" / "minimal" / "bundle.aridi")
        dns = snapshot.sections["network"].data["dns"]
        self.assertIn("2001:db8::53", dns["nameservers"])
        servers = [str(r.ip) for r in snapshot.relations if r.role == Role.DNS_SERVER]
        self.assertIn("2001:db8::53", servers)

    def test_hosts_entries_v4_and_v6_become_relations(self):
        snapshot = snapshot_of(CORPUS / "alpine320" / "minimal" / "bundle.aridi")
        named = {str(r.ip) for r in snapshot.relations if r.role == Role.NAMED_IN_FILE}
        self.assertIn("10.20.30.40", named)
        self.assertIn("2001:db8::40", named)


class LegacyRegressionTest(unittest.TestCase):

    def test_debian12_infrastructure_view(self):
        """The -oi view of 2019: local 127.0.0.1 and DNS server 192.168.65.7."""
        snapshot = snapshot_of(legacy_bundle("debian12"))
        roles = {(str(r.ip), r.role) for r in snapshot.relations}
        self.assertIn(("127.0.0.1", Role.LOCAL), roles)
        self.assertIn(("192.168.65.7", Role.DNS_SERVER), roles)


class SyntheticTest(unittest.TestCase):

    def test_proc_hex_addresses(self):
        self.assertEqual(str(network.ip_from_proc("0100007F")), "127.0.0.1")
        self.assertEqual(str(network.ip_from_proc("00000000000000000000000001000000")), "::1")
        self.assertEqual(str(network.ip_from_proc("B80D0120000000000000000040000000")),
                         "2001:db8::40")
        with self.assertRaises(ValueError):
            network.ip_from_proc("123")

    def test_udp_connected_is_not_listening(self):
        table = ("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt"
                 "   uid  timeout inode\n"
                 "   0: 00000000:158A 00000000:0000 07 00000000:00000000 00:00000000 00000000"
                 "     0        0 1001 2 0\n"
                 "   1: 0100007F:A000 0100007F:0035 01 00000000:00000000 00:00000000 00000000"
                 "  4242        0 1002 2 0\n")
        socks = network.parse_socket_table(table, "udp")
        self.assertEqual([(s["address"], s["port"]) for s in socks], [("0.0.0.0", 5514)])

    def test_socket_owner_with_unknown_uid_and_dead_pid(self):
        tcp = ("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt"
               "   uid  timeout inode\n"
               "   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000"
               "  4242        0 5555 1 0\n").encode()
        data = parse(("network.proc_tcp", tcp), ("network.socket_pids", b"77 5555\n")).data
        [sock] = data["listening"]
        self.assertEqual(sock["uid"], 4242)
        self.assertEqual(sock["processes"], [{"pid": 77, "name": None}])

    def test_ip_link_and_addr_with_peer_names(self):
        link = (b"11: eth0@if762: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue "
                b"state UP mode DEFAULT group default \\    link/ether 46:a7:41:b2:e2:52 brd "
                b"ff:ff:ff:ff:ff:ff link-netnsid 0\n")
        addr = (b"11: eth0    inet 172.22.0.2/16 brd 172.22.255.255 scope global eth0\\       "
                b"valid_lft forever\n11: eth0    inet6 fe80::1/64 scope link \\ valid_lft\n")
        data = parse(("network.ip_link", link), ("network.ip_addr", addr)).data
        [eth0] = data["interfaces"]
        self.assertEqual((eth0["name"], eth0["peer"], eth0["mac"], eth0["state"]),
                         ("eth0", "if762", "46:a7:41:b2:e2:52", "up"))
        self.assertEqual([(a["ip"], a["prefix"]) for a in eth0["addresses"]],
                         [("172.22.0.2", 16), ("fe80::1", 64)])

    def test_addresses_without_ip_tool(self):
        if_inet6 = b"00000000000000000000000000000001 01 80 10 80       lo\n"
        fib_trie = (b"Main:\n  +-- 0.0.0.0/0 3 0 5\n     |-- 127.0.0.1\n        /32 host LOCAL\n"
                    b"Local:\n     |-- 127.0.0.1\n        /32 host LOCAL\n")
        sys_net = b"lo address=00:00:00:00:00:00 operstate=unknown mtu=65536 type=772 ifindex=1\n"
        data = parse(("network.ip_addr", b"", "missing", "-", "tool not found: ip"),
                     ("network.ip_link", b"", "missing", "-", "tool not found: ip"),
                     ("network.sys_class_net", sys_net), ("network.if_inet6", if_inet6),
                     ("network.fib_trie", fib_trie)).data
        self.assertEqual([a["ip"] for a in data["interfaces"][0]["addresses"]], ["::1"])
        self.assertEqual([a["ip"] for a in data["unassigned_addresses"]], ["127.0.0.1"])

    def test_routes_from_proc(self):
        route = (b"Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n"
                 b"eth0\t00000000\t010016AC\t0003\t0\t0\t0\t00000000\n"
                 b"eth0\t000016AC\t00000000\t0001\t0\t0\t0\t0000FFFF\n")
        data = parse(("network.ip_route", b"", "missing", "-", "no ip"),
                     ("network.proc_route", route)).data
        routes = [r for r in data["routes"] if r["family"] == 4]
        self.assertEqual(routes[0], {"destination": "default", "dev": "eth0",
                                     "via": "172.22.0.1", "family": 4})
        self.assertEqual(routes[1]["destination"], "172.22.0.0/16")

    def test_systemd_resolved_stub(self):
        data = parse(("network.resolv_conf", b"nameserver 127.0.0.53\nsearch lan\n"),
                     ("network.resolved_resolv_conf",
                      b"nameserver 192.0.2.53\nnameserver 2001:db8::53\n"),
                     ("network.hosts", b"127.0.0.1 localhost\n"))
        self.assertEqual(data.data["dns"]["upstream"], ["192.0.2.53", "2001:db8::53"])
        servers = [str(r.ip) for r in data.relations if r.role == Role.DNS_SERVER]
        self.assertEqual(servers, ["192.0.2.53", "2001:db8::53"])

    def test_invalid_nameserver_is_kept_apart(self):
        dns = network.parse_resolv_conf("nameserver not-an-ip\nnameserver fe80::1%eth0\n")
        self.assertEqual(dns["invalid"], ["not-an-ip"])
        self.assertEqual(dns["nameservers"], ["fe80::1"])

    def test_relations_sort_v4_and_v6(self):
        addr = (b"1: lo    inet 127.0.0.1/8 scope host lo\n"
                b"1: lo    inet6 ::1/128 scope host \n")
        result = parse(("network.ip_addr", addr))
        self.assertEqual([str(r.ip) for r in result.relations], ["127.0.0.1", "::1"])
        self.assertTrue(all(isinstance(r.ip, (ipaddress.IPv4Address, ipaddress.IPv6Address))
                            for r in result.relations))


if __name__ == "__main__":
    unittest.main()
