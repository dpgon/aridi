"""Area "system" (src/aridi/parsers/system.py), TODO.md 3.1."""

import re
import unittest

from aridi import bundle
from aridi.interpret import interpret
from aridi.model import Status
from aridi.parsers import system
from tests.helpers import (CORPUS, facts, legacy_bundle, legacy_report, make_bundle,
                           sample_name, samples)


def system_of(sample_dir):
    return interpret(bundle.read(sample_dir / "bundle.aridi")).sections["system"]


def parse(*sections):
    raw = bundle.parse(make_bundle(sections))
    return system.parse(dict(raw.sections))


def facts_os_release(block):
    """KEY -> value from the os_release block of facts.txt, with simple unquoting."""
    values = {}
    for line in block.splitlines():
        match = re.fullmatch(r"([A-Z_]+)=(.*)", line.strip())
        if match:
            values[match.group(1).lower()] = match.group(2).strip("\"'")
    return values


class CorpusTest(unittest.TestCase):

    def test_matches_facts_in_every_sample(self):
        for sample in samples():
            with self.subTest(sample=sample_name(sample)):
                section = system_of(sample)
                ref = facts(sample)
                self.assertEqual(section.status, Status.OK)
                self.assertEqual(section.gaps, [])
                data = section.data
                expected = facts_os_release(ref["os_release"])
                if expected:
                    for key in ("id", "version_id", "name", "pretty_name"):
                        self.assertEqual(data["distribution"][key], expected.get(key), key)
                self.assertEqual(data["kernel"]["machine"], ref["arch"].strip())
                self.assertEqual(data["kernel"]["release"], ref["kernel"].split()[2])
                libc_line = ref["libc"].splitlines()[0]
                if libc_line.startswith("musl"):
                    self.assertEqual(data["libc"]["family"], "musl")
                    self.assertRegex(data["libc"]["version"], r"^1\.\d+\.\d+$")
                else:
                    self.assertEqual(data["libc"],
                                     {"family": "glibc", "version": libc_line.split()[-1],
                                      "source": "getconf"})

    def test_alpine_shows_point_release(self):
        dist = system_of(CORPUS / "alpine320" / "minimal").data["distribution"]
        self.assertEqual(dist["id"], "alpine")
        self.assertIsNone(dist["version"])
        self.assertRegex(dist["version_id"], r"^3\.20\.\d+$")

    def test_centos6_without_os_release(self):
        data = system_of(CORPUS / "centos6" / "minimal").data
        self.assertEqual(data["distribution"]["source"], "system.centos_release")
        self.assertEqual(data["distribution"]["id"], "centos")
        self.assertEqual(data["distribution"]["version_id"], "6.10")
        self.assertEqual(data["distribution"]["pretty_name"], "CentOS release 6.10 (Final)")
        self.assertEqual(data["libc"]["version"], "2.12")

    def test_musl_and_glibc(self):
        self.assertEqual(system_of(CORPUS / "alpine320" / "minimal").data["libc"]["family"],
                         "musl")
        for name in ("debian12", "rocky9", "arch", "centos7"):
            libc = system_of(CORPUS / name / "minimal").data["libc"]
            self.assertEqual(libc["family"], "glibc", name)

    def test_x86_64_vm(self):
        data = system_of(CORPUS / "vm-debian12-amd64" / "vm").data
        self.assertEqual(data["kernel"]["machine"], "x86_64")
        self.assertNotIn("linuxkit", data["kernel"]["release"])


class LegacyRegressionTest(unittest.TestCase):
    """Same distribution name and libc as the 2019 aridi (TODO.md 3.1 (e))."""

    def test_same_as_legacy(self):
        for distro in ("debian12", "centos7"):
            with self.subTest(distro=distro):
                report = legacy_report(distro)
                legacy_name = re.search(r"OS Release information:\n \|__(.*)", report).group(1)
                legacy_libc = re.search(r"Libc version:\n \|__(.*)", report).group(1)
                data = interpret(bundle.read(legacy_bundle(distro))).sections["system"].data
                dist = data["distribution"]
                self.assertEqual(f"{dist['name']} {dist['version']}", legacy_name)
                self.assertEqual(f"{data['libc']['family']} {data['libc']['version']}",
                                 legacy_libc)


class SyntheticTest(unittest.TestCase):

    def test_os_release_quoting(self):
        values = system.parse_os_release(
            '# comment\nNAME="My \\"Quoted\\" OS"\nID=my-os\nID_LIKE="rhel fedora"\n'
            "VERSION='1 (One)'\nBROKEN=\"unterminated\nnoequals\n")
        self.assertEqual(values["name"], 'My "Quoted" OS')
        self.assertEqual(values["id"], "my-os")
        self.assertEqual(values["version"], "1 (One)")
        self.assertEqual(values["broken"], "unterminated")
        result = parse(("system.os_release", b"ID=my-os\nID_LIKE=\"rhel fedora\"\n"))
        self.assertEqual(result.data["distribution"]["id_like"], ["rhel", "fedora"])

    def test_os_release_from_usr_lib(self):
        result = parse(("system.os_release", b"", "na", "-", "not found"),
                       ("system.os_release_usr", b"ID=arch\n"))
        self.assertEqual(result.data["distribution"]["source"], "system.os_release_usr")

    def test_lsb_release_fallback(self):
        result = parse(("system.lsb_release",
                        b'DISTRIB_ID=Ubuntu\nDISTRIB_RELEASE=14.04\nDISTRIB_CODENAME=trusty\n'
                        b'DISTRIB_DESCRIPTION="Ubuntu 14.04.6 LTS"\n'))
        dist = result.data["distribution"]
        self.assertEqual((dist["id"], dist["version_id"], dist["pretty_name"]),
                         ("ubuntu", "14.04", "Ubuntu 14.04.6 LTS"))

    def test_redhat_and_suse_release_lines(self):
        dist = parse(("system.redhat_release",
                      b"Red Hat Enterprise Linux Server release 7.9 (Maipo)\n")
                     ).data["distribution"]
        self.assertEqual((dist["id"], dist["name"], dist["version_id"], dist["version"]),
                         ("rhel", "Red Hat Enterprise Linux Server", "7.9", "7.9 (Maipo)"))
        dist = parse(("system.suse_release", b"openSUSE 13.1 (x86_64)\nVERSION = 13.1\n")
                     ).data["distribution"]
        self.assertEqual((dist["id"], dist["name"]), ("suse", "openSUSE 13.1 (x86_64)"))

    def test_unknown_distribution_is_a_gap_with_the_real_cause(self):
        result = parse(("system.os_release", b"", "denied", 1, "cat: Permission denied"))
        self.assertIsNone(result.data["distribution"])
        [gap] = [g for g in result.gaps if g.item == "distribution"]
        self.assertEqual(gap.status, Status.DENIED)
        result = parse()
        self.assertEqual({g.item: g.status for g in result.gaps},
                         {"distribution": Status.ERROR, "kernel": Status.ERROR,
                          "architecture": Status.ERROR, "libc": Status.ERROR})

    def test_libc_variants(self):
        musl = b"musl libc (x86_64)\nVersion 1.2.4_git20230717\nDynamic Program Loader\n"
        self.assertEqual(parse(("system.ldd_version", musl)).data["libc"],
                         {"family": "musl", "version": "1.2.4_git20230717", "source": "ldd"})
        result = parse(("system.ldd_version", b"", "missing", "-", "tool not found: ldd"),
                       ("system.musl_loader", b"/lib/ld-musl-x86_64.so.1\n"))
        self.assertEqual(result.data["libc"]["family"], "musl")
        self.assertEqual([g.item for g in result.gaps if g.item.startswith("libc")],
                         ["libc version"])
        glibc = b"ldd (Ubuntu GLIBC 2.39-0ubuntu8.9) 2.39\nCopyright (C) 2024\n"
        self.assertEqual(parse(("system.ldd_version", glibc)).data["libc"]["version"], "2.39")

    def test_kernel_from_proc_version_only(self):
        result = parse(("system.proc_version", b"Linux version 3.10.0-1160.el7.x86_64 (x)\n"))
        self.assertEqual(result.data["kernel"]["release"], "3.10.0-1160.el7.x86_64")


if __name__ == "__main__":
    unittest.main()
