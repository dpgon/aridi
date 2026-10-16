"""Volatile areas: processes, load, sessions and connections (TODO.md 3.12 to 3.15)."""

import re
import unittest
from datetime import datetime, timezone

from aridi import bundle, ports
from aridi.interpret import interpret
from aridi.model import Role, Status
from aridi.parsers import connections, load, processes, sessions
from tests.helpers import (CORPUS, facts, legacy_bundle, legacy_report, make_bundle,
                           sample_name, samples)

VMS = ("vm-debian12-arm64", "vm-rocky9-arm64", "vm-debian12-amd64")


def snapshot_of(path):
    return interpret(bundle.read(path))


def sections(*items):
    return dict(bundle.parse(make_bundle(items)).sections)


class ProcessesTest(unittest.TestCase):

    def test_every_sample_any_number_of_processes(self):
        """docs/MVP.md n.º 17: fewer than 10 processes broke the top 10 in 2019."""
        for sample in samples():
            with self.subTest(sample=sample_name(sample)):
                section = snapshot_of(sample / "bundle.aridi").sections["processes"]
                self.assertEqual(section.status, Status.OK)
                self.assertTrue(section.volatile)
                data = section.data
                self.assertEqual(data["count"], len(data["processes"]))
                self.assertLessEqual(len(data["top_memory"]), 10)

    def test_uid_without_account_shows_the_uid(self):
        """docs/MVP.md n.º 16."""
        for sample in samples():
            with self.subTest(sample=sample_name(sample)):
                data = snapshot_of(sample / "bundle.aridi").sections["processes"].data
                found = [p for p in data["processes"] if p["uid"] == 4242]
                self.assertTrue(found)
                self.assertEqual({p["user"] for p in found}, {"4242"})

    def test_long_lived_processes_like_ps(self):
        for name in VMS:
            with self.subTest(sample=name):
                sample = CORPUS / name / "vm"
                ours = {p["pid"]: p for p in snapshot_of(sample / "bundle.aridi")
                        .sections["processes"].data["processes"]}
                ps = [line.split() for line in facts(sample)["processes"].splitlines()[1:]]
                # PID 1 and the scenario processes exist in both, with the same uid.
                for pid, uid, _, comm in (p[:4] for p in ps if len(p) >= 4):
                    if comm in ("systemd", "socat") or uid == "4242":
                        self.assertEqual(ours[int(pid)]["uid"], int(uid), comm)

    def test_synthetic_zombie_and_cpu(self):
        stat = (b"1 (init) S 0 1 1 0 -1 4194560 0 0 0 0 100 50 0 0 20 0 1 0 10 0 0\n"
                b"42 (my (odd) name) Z 1 42 42 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 500 0 0\n")
        status = b"1 0 1024 1\n42 4242 0 1\n"
        result = processes.parse(sections(("processes.stat", stat),
                                          ("processes.status", status),
                                          ("processes.uptime", b"100.00 50.00\n"),
                                          ("processes.clk_tck", b"100\n")))
        by_pid = {p["pid"]: p for p in result.data["processes"]}
        self.assertEqual(by_pid[42]["comm"], "my (odd) name")
        self.assertEqual(result.data["zombies"], [42])
        self.assertEqual(by_pid[1]["cpu"], round(100 * 1.5 / 99.9, 2))
        self.assertEqual(by_pid[42]["user"], "4242")

    def test_without_getconf_uses_and_declares_user_hz(self):
        result = processes.parse(sections(
            ("processes.stat", b"1 (init) S 0 1 1 0 -1 0 0 0 0 0 10 0 0 0 20 0 1 0 0 0 0\n"),
            ("processes.uptime", b"10.0 1.0\n"),
            ("processes.clk_tck", b"", "missing", "-", "tool not found: getconf")))
        self.assertEqual((result.data["clk_tck"], result.data["clk_tck_source"]),
                         (100, "default"))


class LoadTest(unittest.TestCase):

    def test_every_sample(self):
        for sample in samples():
            with self.subTest(sample=sample_name(sample)):
                section = snapshot_of(sample / "bundle.aridi").sections["load"]
                self.assertEqual(section.status, Status.OK)
                self.assertEqual(section.gaps, [])
                data = section.data
                self.assertGreaterEqual(data["interval_seconds"], 0.9)
                self.assertLess(data["interval_seconds"], 5)
                self.assertIsNotNone(data["cpu"]["last_second"])

    def test_memory_like_legacy(self):
        """Debian 12 reference: 7934 MB, 18% used, 63% buffers/cache, 20% free (±5)."""
        report = legacy_report("debian12")
        total_mb = int(re.search(r"Total memory of (\d+) MB", report).group(1))
        legacy = {key: int(re.search(rf"\|__(\d+)% {key}", report).group(1))
                  for key in ("used", "buffers/cache", "free")}
        mem = snapshot_of(legacy_bundle("debian12")).sections["load"].data["memory"]
        self.assertEqual(round(mem["total"] / 1024 / 1024), total_mb)
        ours = {"used": mem["used"], "buffers/cache": mem["buffers"] + mem["cache"],
                "free": mem["free"]}
        for key, value in ours.items():
            self.assertLessEqual(abs(100 * value / mem["total"] - legacy[key]), 5, key)

    def test_disk_busy_percent(self):
        """docs/MVP.md n.º 13: 2019 divided the busy time by 1000 once too often."""
        line = "   8       0 sda {r} 0 {rs} 0 {w} 0 {ws} 0 0 {ms} 0\n"
        first = line.format(r=100, rs=800, w=10, ws=80, ms=1000)
        second = line.format(r=150, rs=1200, w=30, ws=240, ms=1500)
        [disk] = load.disk_usage(load.parse_diskstats(first), load.parse_diskstats(second), 2.0)
        self.assertEqual(disk["busy_percent"], 25.0)
        self.assertEqual(disk["reads_per_second"], 25.0)
        self.assertEqual(disk["write_bytes_per_second"], 160 * 512 / 2)


class SessionsTest(unittest.TestCase):

    def test_vm_sessions(self):
        for name in VMS:
            with self.subTest(sample=name):
                snapshot = snapshot_of(CORPUS / name / "vm" / "bundle.aridi")
                data = snapshot.sections["sessions"].data
                active = [s for s in data["active"] if s["user"] == "alice"]
                self.assertEqual([s["host"] for s in active], ["127.0.0.1"])
                hosts = {e["host"] for e in data["logins"] if e["user"] == "alice"}
                self.assertTrue({"127.0.0.1", "::1"} <= hosts, hosts)
                self.assertGreaterEqual(data["login_counts"]["day"], 3)
                failed = [e for e in data["failed"] if e["user"] == "nosuchuser"]
                self.assertTrue(failed)
                self.assertEqual(failed[0]["host"], "127.0.0.1")
                # Loopback sources are not relations; the Lima host (limactl shell) is.
                sources = {str(r.ip) for r in snapshot.relations if r.source == "sessions"}
                self.assertEqual(sources, {"192.168.5.2"})

    def test_containers_without_sessions(self):
        for sample in samples():
            if sample.name == "vm":
                continue
            with self.subTest(sample=sample_name(sample)):
                section = snapshot_of(sample / "bundle.aridi").sections["sessions"]
                self.assertEqual(section.status, Status.OK)

    def test_utmpdump_new_and_old_formats(self):
        new = ("[7] [01234] [ts/0] [alice   ] [pts/0       ] [192.0.2.30          ] "
               "[192.0.2.30     ] [2026-10-15T16:26:03,123456+00:00]\n"
               "[8] [01234] [    ] [        ] [pts/0       ] [                    ] "
               "[0.0.0.0        ] [2026-10-15T16:30:00,000000+00:00]\n")
        old = ("[7] [01234] [ts/0] [bob     ] [pts/1       ] [2001:db8::9         ] "
               "[2001:db8::9    ] [Thu Oct 15 16:26:03 2026 UTC]\n")
        records = sessions.parse_utmpdump(new + old)
        self.assertEqual([(r["type"], r["user"]) for r in records],
                         [("7", "alice"), ("8", ""), ("7", "bob")])
        self.assertEqual(records[0]["time"], datetime(2026, 10, 15, 16, 26, 3, 123456,
                                                      tzinfo=timezone.utc))
        self.assertEqual(records[2]["time"], datetime(2026, 10, 15, 16, 26, 3,
                                                      tzinfo=timezone.utc))

    def test_journal_syslog_relations_and_counts(self):
        journal = (
            "2026-10-15T16:00:00+0000 h sshd[1]: Accepted publickey for alice from "
            "192.0.2.30 port 5000 ssh2: ED25519 SHA256:x\n"
            "2026-10-15T16:01:00+0000 h sshd[2]: Invalid user admin from 203.0.113.50 port 1\n"
            "2026-10-15T16:01:05+0000 h sshd[2]: Connection closed by invalid user admin "
            "203.0.113.50 port 1 [preauth]\n"
            "2026-09-01T10:00:00+0000 h sshd[3]: Failed password for root from 2001:db8::77 "
            "port 2 ssh2\n")
        syslog = ("Oct 15 15:00:00 h sshd[9]: Failed password for invalid user x from "
                  "198.51.100.1 port 3 ssh2\n")
        result = sessions.parse(sections(
            ("meta.date_utc", b"2026-10-15T17:00:00Z\n"),
            ("sessions.journal_sshd", journal.encode()),
            ("sessions.log_secure", syslog.encode())))
        data = result.data
        self.assertEqual(data["failed_total"], 3)
        self.assertEqual(data["failed_counts"], {"day": 2, "week": 2, "month": 2})
        self.assertEqual(data["login_counts"]["day"], 1)
        roles = {(str(r.ip), r.role) for r in result.relations}
        self.assertEqual(roles, {("192.0.2.30", Role.LOGIN_SOURCE),
                                 ("203.0.113.50", Role.FAILED_LOGIN_SOURCE),
                                 ("2001:db8::77", Role.FAILED_LOGIN_SOURCE),
                                 ("198.51.100.1", Role.FAILED_LOGIN_SOURCE)})

    def test_dates_in_another_language_are_unknown_not_wrong(self):
        self.assertIsNone(sessions.parse_time("jue oct 15 16:26:03 2026"))
        [login] = sessions.parse_last("alice pts/0 1.2.3.4 jue oct 15 16:26:03 2026 - 16:30\n"
                                      "alice pts/0 1.2.3.4 Thu Oct 15 16:26:03 2026 - Thu Oct "
                                      "15 16:30:00 2026 (00:03)\n")
        self.assertEqual(login["time"].day, 15)

    def test_last_and_who_fallback(self):
        last = ("alice    pts/0        192.0.2.30       Thu Oct 15 16:26:03 2026   still "
                "logged in\nreboot   system boot  6.1.0            Thu Oct 15 16:00:00 2026\n")
        who = "alice    pts/0        2026-10-15 16:26 (192.0.2.30)\n"
        data = sessions.parse(sections(("sessions.last", last.encode()),
                                       ("sessions.who", who.encode()))).data
        self.assertEqual(data["sources"], ["who", "last"])
        self.assertEqual([(s["user"], s["host"]) for s in data["active"]],
                         [("alice", "192.0.2.30")])
        self.assertEqual([e["user"] for e in data["logins"]], ["alice"])


class ConnectionsTest(unittest.TestCase):

    TCP = ("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt"
           "   uid  timeout inode\n"
           "   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000"
           "     0        0 100 1 0\n"
           "   1: 0200160A:0016 1E0200C0:C350 01 00000000:00000000 00:00000000 00000000"
           "     0        0 101 1 0\n"
           "   2: 0200160A:D431 0A3364C6:01BB 01 00000000:00000000 00:00000000 00000000"
           "  4242        0 102 1 0\n"
           "   3: 0100007F:1F90 0100007F:D000 06 00000000:00000000 00:00000000 00000000"
           "     0        0 0 1 0\n")

    def test_directions_services_and_relations(self):
        result = connections.parse(sections(
            ("network.proc_tcp", self.TCP.encode()),
            ("network.socket_pids", b"9 101\n"),
            ("network.process_names", b"9 0 sshd\n"),
            ("users.passwd", b"root:x:0:0::/root:/bin/sh\n")))
        conns = {c["remote"]: c for c in result.data["connections"]}
        self.assertEqual(set(conns), {"192.0.2.30", "198.100.51.10"})
        ssh = conns["192.0.2.30"]
        self.assertEqual((ssh["direction"], ssh["service"], ssh["user"]), ("in", "ssh", "root"))
        self.assertEqual(ssh["processes"], [{"pid": 9, "name": "sshd"}])
        https = conns["198.100.51.10"]
        self.assertEqual((https["direction"], https["remote_port"], https["user"]),
                         ("out", 443, "4242"))
        self.assertEqual({(str(r.ip), r.role) for r in result.relations},
                         {("192.0.2.30", Role.PEER_IN), ("198.100.51.10", Role.PEER_OUT)})

    def test_ipv6_connection(self):
        tcp6 = ("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt"
                "   uid  timeout inode\n"
                "   0: B80D0120000000000000000001000000:9C40 B80D0120000000000000000002000000"
                ":0050 01 00000000:00000000 00:00000000 00000000  1000 0 7 1 0\n")
        result = connections.parse(sections(("network.proc_tcp6", tcp6.encode())))
        [conn] = result.data["connections"]
        self.assertEqual((conn["local"], conn["remote"], conn["service"]),
                         ("2001:db8::1", "2001:db8::2", "http"))

    def test_vm_ssh_session_is_an_incoming_connection(self):
        for name in VMS:
            with self.subTest(sample=name):
                data = snapshot_of(CORPUS / name / "vm" / "bundle.aridi").sections[
                    "connections"].data
                ssh = [c for c in data["connections"]
                       if c["local_port"] == 22 and c["direction"] == "in"]
                self.assertTrue(ssh)
                self.assertEqual(ssh[0]["service"], "ssh")

    def test_ports_table(self):
        self.assertEqual(ports.name(22), "ssh")
        self.assertIsNone(ports.name(65000))


if __name__ == "__main__":
    unittest.main()
