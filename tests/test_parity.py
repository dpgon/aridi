"""Final regression against the 2019 aridi (TODO.md 4.1, tests/parity.md).

tests/parity/<distro>-<network>/ holds what the unmodified 2019 aridi and the new collector
saw on the same container, one right after the other (tests/legacy/reference.sh, kept in
the git history after phase 4.2). Every value that the 2019 report gives right must come
out of the new snapshot with the same value. Where 2019 was wrong, the test says so and
checks the right value instead.
"""

import ipaddress
import re
import unittest

from aridi import bundle
from aridi.interpret import interpret
from aridi.model import Role
from aridi.relations import consolidate
from tests.helpers import REPO

PARITY = REPO / "tests" / "parity"
REFERENCES = ("debian12-plain", "debian12-none", "debian12-bridge",
              "centos7-plain", "centos7-none", "centos7-bridge")
# Symbolic links to SUID files that 2019 listed as SUID files (checked with "ls -l" in both
# images: /usr/bin/sg -> newgrp; the dbus helper -> /usr/libexec/dbus-1/...).
SUID_SYMLINKS = {
    "debian12": {"/usr/bin/sg"},
    "centos7": {"/usr/bin/sg", "/usr/lib64/dbus-1/dbus-daemon-launch-helper"},
}


def detail(report, title, nth=0):
    """Body of the nth "|| title ||" block of the detailed part, or None if 2019 lost it."""
    detailed = report.split("INFRASTRUCTURE REPORT")[0]
    parts = re.split(r"(?m)^\|\|\s+(.+?)\s+\|\|$", detailed)
    found = [parts[i + 1] for i in range(1, len(parts), 2) if parts[i] == title]
    if len(found) <= nth:
        return None
    return "\n".join(line for line in found[nth].splitlines() if not re.fullmatch(r"=+", line))


def summary(report):
    return report.split("SUMMARIZED INFORMATION")[1]


def ipv4(value):
    try:
        return ipaddress.ip_address(value).version == 4
    except ValueError:
        return False


class Reference:
    """The 2019 report and the new snapshot of one reference machine."""

    def __init__(self, name):
        self.name = name
        self.dir = PARITY / name
        self.report = (self.dir / "report.txt").read_text(encoding="utf-8")
        self.badfiles = (self.dir / "badfiles.txt").read_text(encoding="utf-8")
        self.snapshot = interpret(bundle.read(self.dir / "bundle.aridi"))
        # "plain" is the image without tests/corpus/scenario.sh.
        self.scenario = not name.endswith("-plain")
        self.data = {name: section.data for name, section in self.snapshot.sections.items()}


class ParityTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.refs = [Reference(name) for name in REFERENCES]

    def each(self, block=None, nth=0):
        """[(reference, 2019 block)] for every reference where 2019 has that block."""
        found = [(ref, detail(ref.report, block, nth) if block else None) for ref in self.refs]
        return [(ref, body) for ref, body in found if not block or body is not None]

    def test_references_exist(self):
        self.assertEqual([r.name for r in self.refs], list(REFERENCES))
        for ref in self.refs:
            self.assertIn("SUMMARIZED INFORMATION", ref.report, ref.name)

    # General information

    def test_cpu_architecture_and_sockets(self):
        for ref, body in self.each("CPU information"):
            with self.subTest(reference=ref.name):
                cpu = ref.data["hardware"]["cpu"]
                self.assertEqual(re.search(r"Architect\.:\s*(\S+)", body)[1], cpu["architecture"])
                self.assertEqual(int(re.search(r"Sockets:\s*(\d+)", body)[1]), cpu["sockets"])
                # 2019 gives "Vendor: " and "Cores/sock: 0" on arm64 (docs/MVP.md n.º 11).
                self.assertRegex(body, r"Vendor:\s*\n")
                self.assertTrue(cpu["vendor"] and cpu["cores"] > 0)

    def test_ram_and_swap(self):
        for ref, body in self.each("RAM information"):
            with self.subTest(reference=ref.name):
                memory = ref.data["hardware"]["memory"]
                self.assertEqual(int(re.search(r"Memory:\s*(\d+) kB", body)[1]) * 1024,
                                 memory["total"])
                self.assertEqual(int(re.search(r"SWAP:\s*(\d+) kB", body)[1]) * 1024,
                                 memory["swap_total"])

    def test_kernel(self):
        for ref, body in self.each("OS Kernel information"):
            with self.subTest(reference=ref.name):
                kernel = ref.data["system"]["kernel"]
                self.assertEqual(body.strip().splitlines()[-1],
                                 f"{kernel['ostype']} {kernel['release']} {kernel['version']}")

    def test_distribution(self):
        for ref, _ in self.each():
            with self.subTest(reference=ref.name):
                line = re.search(r"OS Release information:\n \|__(.+)", summary(ref.report))[1]
                self.assertEqual(line, ref.data["system"]["distribution"]["pretty_name"])

    def test_libc(self):
        for ref, body in self.each("Libc information"):
            with self.subTest(reference=ref.name):
                libc = ref.data["system"]["libc"]
                self.assertEqual(body.strip().splitlines()[-1],
                                 f"{libc['family']} {libc['version']}")

    def test_packages_same_names(self):
        for ref, body in self.each("Packages information"):
            with self.subTest(reference=ref.name):
                rows = re.findall(r"(?m)^(\S+)\s+- (\S+)$", body)
                ours = ref.data["packages"]
                mine = [p for p in ours["packages"] if p["name"] != "gpg-pubkey"]
                if ref.name.startswith("centos7"):
                    # yum prints "name.arch"; gpg-pubkey keys are not packages for yum.
                    legacy = {name.rsplit(".", 1)[0] for name, _ in rows}
                else:
                    legacy = {name for name, _ in rows}
                self.assertEqual(len(rows), len(mine))
                self.assertEqual(legacy, {p["name"] for p in mine})

    def test_rpm_versions(self):
        """yum and rpm agree on epoch:version-release (dpkg is below)."""
        for ref, body in self.each("Packages information"):
            with self.subTest(reference=ref.name):
                if not ref.name.startswith("centos7"):
                    continue
                legacy = {(name.rsplit(".", 1)[0], version)
                          for name, version in re.findall(r"(?m)^(\S+)\s+- (\S+)$", body)}
                ours = {(p["name"], p["version"]) for p in ref.data["packages"]["packages"]
                        if p["name"] != "gpg-pubkey"}
                self.assertEqual(legacy, ours)

    def test_dpkg_versions_where_2019_was_right(self):
        """2019 printed the source version (docs/MVP.md n.º 3), the new one the binary one."""
        for ref, body in self.each("Packages information"):
            with self.subTest(reference=ref.name):
                if not ref.name.startswith("debian12"):
                    continue
                legacy = dict(re.findall(r"(?m)^(\S+)\s+- (\S+)$", body))
                ours = {p["name"]: p["version"] for p in ref.data["packages"]["packages"]}
                # A binary package differs from its source only by a binNMU suffix ("+b2")
                # or by its own epoch ("1:"): nothing else may differ.
                plain = lambda v: re.sub(r"\+b\d+$", "", re.sub(r"^\d+:", "", v))
                self.assertEqual({n: plain(v) for n, v in legacy.items()},
                                 {n: plain(v) for n, v in ours.items()})
                self.assertEqual(set(legacy), set(ours))

    def test_disks(self):
        for ref, body in self.each("Disk/Partitions information"):
            with self.subTest(reference=ref.name):
                legacy = set(re.findall(r"(?m)^(\w+)\s+- Size:", body))
                ours = {d["name"] for d in ref.data["storage"]["devices"]}
                self.assertTrue(legacy, body)
                self.assertLessEqual(legacy, ours)

    def test_permissions(self):
        for ref, _ in self.each():
            with self.subTest(reference=ref.name):
                perms = ref.data["permissions"]
                bad = ref.badfiles
                nosticky = set(re.findall(r"'(.+)' dir has write permission for all user and no "
                                          r"sticky bit", bad))
                writable = set(re.findall(r"'(.+)' file has write permission for all", bad))
                suid = set(re.findall(r"'(.+)' file has SUID", bad))
                sgid = set(re.findall(r"'(.+)' file has GUID", bad))
                self.assertEqual(nosticky,
                                 {f["path"] for f in perms["world_writable_dirs_no_sticky"]})
                self.assertEqual(writable, {f["path"] for f in perms["world_writable_files"]})
                self.assertEqual(sgid, {f["path"] for f in perms["sgid"]})
                # 2019 followed symbolic links and counted their targets twice; find -perm
                # does not follow them.
                links = SUID_SYMLINKS[ref.name.split("-")[0]]
                self.assertLessEqual(links, suid)
                self.assertEqual(suid - links, {f["path"] for f in perms["suid"]})

    # Specific information

    def test_hostname_hostid_and_banners(self):
        for ref, body in self.each("Hostnames information"):
            with self.subTest(reference=ref.name):
                identity = ref.data["identity"]
                hostname = re.search(r"/etc/hostname\s*\n-+\n(\S+)", body)[1]
                self.assertEqual(hostname, identity["hostname"])
                self.assertEqual(re.search(r"hostid\s*\n-+\n(\S+)", body)[1], identity["hostid"])
                legacy = set(re.findall(r"(?m)^\s+(/etc/(?:issue|issue\.net|motd))\s*$", body))
                self.assertEqual(legacy, set(identity["banners"]))
                issue_net = identity["banners"]["/etc/issue.net"]["text"].strip()
                self.assertIn(issue_net, body)

    def test_hosts_interfaces_and_dns(self):
        """Only without bridge: with eth0@ifN 2019 loses the whole area (MVP n.º 15)."""
        for ref, body in self.each("Network information"):
            with self.subTest(reference=ref.name):
                network = ref.data["network"]
                hosts = re.findall(r"(?m)^\s+(\S+) - (\S+)$", body.split("Interfaces")[0])
                ours = {(h["ip"], name) for h in network["hosts"] for name in h["names"]}
                self.assertTrue(hosts)
                self.assertLessEqual(set(hosts), ours)
                self.assertEqual({ip for ip, _ in hosts},
                                 {h["ip"] for h in network["hosts"] if ipv4(h["ip"])})
                table = body.split("Interfaces")[1].split("Routes information")[0]
                rows = [line.split() for line in table.splitlines()
                        if line.strip() and not re.match(r"\s*(-+|IFACE\b)", line)]
                interfaces = {i["name"]: i for i in network["interfaces"]}
                self.assertTrue(rows)
                for fields in rows:
                    name, _, peer = fields[0].partition("@")
                    self.assertIn(name, interfaces)
                    if peer:
                        self.assertEqual(interfaces[name]["peer"], peer)
                    # 2019 prints the link address of tunnels ("0.0.0.0", "::"): only
                    # Ethernet-like addresses are compared.
                    if re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", fields[1]):
                        self.assertEqual(interfaces[name]["mac"], fields[1])
                    if len(fields) > 2:
                        self.assertIn(fields[2], [f"{a['ip']}/{a['prefix']}"
                                                  for a in interfaces[name]["addresses"]])
                dns = re.findall(r"(?m)^ \|__(\S+)$", body.split("DNS:")[1])
                self.assertEqual(dns, [n for n in network["dns"]["nameservers"] if ipv4(n)])

    def test_bridge_network_that_2019_lost(self):
        for ref in self.refs:
            if not ref.name.endswith("bridge"):
                continue
            with self.subTest(reference=ref.name):
                self.assertIsNone(detail(ref.report, "Network information"))
                eth0 = next(i for i in ref.data["network"]["interfaces"] if i["name"] == "eth0")
                self.assertRegex(eth0["peer"], r"^if\d+$")
                self.assertTrue(ref.data["network"]["routes"])

    # Volatile information

    def test_total_memory_in_mb(self):
        for ref, body in self.each("Memory information"):
            with self.subTest(reference=ref.name):
                mb = int(re.search(r"Total memory of (\d+) MB", body)[1])
                # 2019 rounds to the nearest MB (8124256 kB is 7933.8 MB).
                self.assertEqual(mb, round(ref.data["load"]["memory"]["total"] / 2**20))

    def test_uptime(self):
        """The collector runs right after 2019: same uptime, a few seconds later."""
        for ref, body in self.each("CPU information", nth=1):
            with self.subTest(reference=ref.name):
                days, h, m, s = re.search(r"(?:(\d+) days?, )?(\d+):(\d+):(\d+) up", body).groups()
                legacy = int(days or 0) * 86400 + int(h) * 3600 + int(m) * 60 + int(s)
                self.assertLessEqual(0, ref.data["load"]["uptime_seconds"] - legacy)
                self.assertLess(ref.data["load"]["uptime_seconds"] - legacy, 120)

    def test_failed_logins(self):
        for ref, body in self.each("Users information"):
            with self.subTest(reference=ref.name):
                failed = int(re.search(r"(\d+) failed logins in btmp", body)[1])
                self.assertEqual(failed, ref.data["sessions"]["failed_total"])

    def test_listening_sockets(self):
        """2019 saw tcp4 and udp4 (udp as "CLOSE"); the new one also tcp6 (MVP n.º 16)."""
        for ref, body in self.each("Network live information"):
            with self.subTest(reference=ref.name):
                listening = ref.data["network"]["listening"]
                ours = {(s["proto"], s["address"], s["port"]):
                        [p["name"] for p in s["processes"]] for s in listening}
                tcp = re.findall(r"\|__([0-9.]+):(\d+)\s+- \S+\s+LISTEN\s+\S+\s+(\S+)",
                                 body.split("UDP Connections")[0])
                udp = re.findall(r"\|__([0-9.]+):(\d+)\s+- \S+\s+CLOSE\s+\S+\s+(\S+)",
                                 body.split("UDP Connections")[1])
                if ref.scenario:
                    self.assertTrue(tcp and udp)
                    self.assertIn(("tcp6", "::", 8080), ours)
                for proto, rows in (("tcp", tcp), ("udp", udp)):
                    for address, port, process in rows:
                        self.assertEqual(ours[(proto, address, int(port))], [process])

    # Other information

    def test_carving(self):
        for ref, _ in self.each():
            with self.subTest(reference=ref.name):
                text = ref.report
                for source, block in (("etc", "/etc information"),
                                      ("log", "/var/log information")):
                    legacy = set(re.findall(r"\|__(\S+) named in file", detail(text, block)))
                    ours = {a["ip"] for a in ref.data["carving"]["addresses"]
                            if any(m["source"] == source for m in a["mentions"])}
                    if ref.scenario:
                        self.assertTrue(legacy)
                    self.assertEqual(legacy, {ip for ip in ours if ipv4(ip)})

    def test_infrastructure(self):
        """Every address of the 2019 map is in the new one, local ones still local."""
        for ref, _ in self.each():
            with self.subTest(reference=ref.name):
                infra = ref.report.split("INFRASTRUCTURE REPORT")[1].split("SUMMARIZED")[0]
                local, remote = infra.split("Remote IP Address:")
                nodes = {str(n.ip): n for n in consolidate(ref.snapshot.relations)}
                for ip in re.findall(r"(?m)^ \|__(\S+)$", local):
                    self.assertTrue(nodes[ip].local, ip)
                for ip in re.findall(r"(?m)^ \|__(\S+)$", remote):
                    self.assertIn(ip, nodes)
                # 2019 puts 127.0.0.1 among the remote ones when it loses the network area.
                self.assertTrue(nodes["127.0.0.1"].local)
                if "DNS Server" in infra:
                    dns = {str(r.ip) for r in ref.snapshot.relations if r.role == Role.DNS_SERVER}
                    self.assertIn(re.search(r"\|__(\S+)\n\s+\|\s+\|__DNS Server", infra)[1], dns)


if __name__ == "__main__":
    unittest.main()
