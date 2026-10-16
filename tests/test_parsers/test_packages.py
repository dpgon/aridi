"""Area "packages" (src/aridi/parsers/packages.py), TODO.md 3.3."""

import re
import unittest

from aridi import bundle
from aridi.interpret import interpret
from aridi.model import Status
from aridi.parsers import packages
from tests.helpers import (CORPUS, facts, legacy_bundle, legacy_report, make_bundle,
                           sample_name, samples)


def packages_of(path):
    return interpret(bundle.read(path)).sections["packages"]


def parse(*sections):
    return packages.parse(dict(bundle.parse(make_bundle(sections)).sections))


def facts_packages(block, manager):
    """Set of comparable package strings from the packages block of facts.txt."""
    found = set()
    for line in block.splitlines():
        if not line.strip():
            continue
        if manager == "rpm":                      # NAME  EPOCH:VERSION-RELEASE  ARCH
            name, version, arch = line.split("\t")
            if name != "gpg-pubkey":
                found.add(f"{name} {version.removeprefix('(none):')} {arch}")
        elif manager == "dpkg":                   # NAME[:ARCH]  VERSION  ARCH
            name, version, arch = line.split("\t")
            found.add(f"{name.split(':')[0]} {version} {arch}")
        else:                                     # pacman "NAME VERSION", apk "NAME-VERSION"
            found.add(line.strip())
    return found


def as_facts(package):
    if package["manager"] == "apk":
        return f"{package['name']}-{package['version']}"
    if package["manager"] == "pacman":
        return f"{package['name']} {package['version']}"
    return f"{package['name']} {package['version']} {package['arch']}"


class CorpusTest(unittest.TestCase):

    def test_exactly_the_packages_of_facts(self):
        for sample in samples():
            with self.subTest(sample=sample_name(sample)):
                section = packages_of(sample / "bundle.aridi")
                self.assertEqual(section.status, Status.OK)
                self.assertEqual(section.gaps, [])
                [manager] = section.data["managers"]
                expected = facts_packages(facts(sample)["packages"], manager)
                got = {as_facts(p) for p in section.data["packages"]}
                self.assertEqual(got, expected)
                self.assertEqual(section.data["count"], len(expected))

    def test_fedora_and_alpine_have_packages(self):
        """docs/MVP.md n.º 14: no packages in Fedora and Alpine in 2019."""
        for name, manager in (("fedora44", "rpm"), ("alpine320", "apk"), ("arch", "pacman"),
                              ("leap156", "rpm")):
            with self.subTest(sample=name):
                data = packages_of(CORPUS / name / "minimal" / "bundle.aridi").data
                self.assertGreater(data["managers"][manager], 10)

    def test_debian_binary_version(self):
        data = packages_of(CORPUS / "debian12" / "minimal" / "bundle.aridi").data
        libc = [p for p in data["packages"] if p["name"] == "libc6"]
        self.assertEqual(len(libc), 1)
        self.assertRegex(libc[0]["version"], r"^2\.36-")


class LegacyRegressionTest(unittest.TestCase):

    def test_counts_same_as_legacy(self):
        for distro, label in (("debian12", "DEB"), ("centos7", "RPM")):
            with self.subTest(distro=distro):
                legacy = int(re.search(rf"Total {label} packages \(\w+\):\n \|__(\d+)",
                                       legacy_report(distro)).group(1))
                data = packages_of(legacy_bundle(distro)).data
                # 2019 used "yum list installed", which does not list gpg-pubkey either.
                self.assertEqual(data["count"], legacy)
        self.assertEqual(packages_of(legacy_bundle("debian12")).data["count"], 141)
        self.assertEqual(packages_of(legacy_bundle("centos7")).data["gpg_pubkeys"], 2)


class SyntheticTest(unittest.TestCase):

    def test_dpkg_only_installed(self):
        status = (b"Package: kept\nStatus: install ok installed\nVersion: 1:2.0-1\n"
                  b"Architecture: amd64\n\nPackage: removed\nStatus: deinstall ok config-files\n"
                  b"Version: 1.0\n\nPackage: half\nStatus: install ok half-installed\n\n")
        data = parse(("packages.dpkg", status)).data
        self.assertEqual([(p["name"], p["version"]) for p in data["packages"]],
                         [("kept", "1:2.0-1")])

    def test_rpm_epoch_and_gpg_pubkey(self):
        rpm = (b"bash\t(none)\t5.1.8\t6.el9\taarch64\n"
               b"openssl\t1\t3.0.7\t27.el9\taarch64\n"
               b"gpg-pubkey\t(none)\t350d275d\t6279464b\t(none)\n")
        data = parse(("packages.rpm", rpm)).data
        self.assertEqual([p["version"] for p in data["packages"]],
                         ["5.1.8-6.el9", "1:3.0.7-27.el9"])
        self.assertEqual(data["gpg_pubkeys"], 1)
        self.assertEqual(data["count"], 2)

    def test_rpm_database_without_rpm_tool(self):
        result = parse(("packages.rpm", b"", "missing", "-", "tool not found: rpm"))
        self.assertEqual([(g.item, g.status) for g in result.gaps], [("rpm", Status.MISSING)])

    def test_truncated_database_is_a_gap(self):
        big = b"".join(b"Package: p%d\nStatus: install ok installed\nVersion: 1\n\n" % n
                       for n in range(50))
        result = parse(("packages.dpkg", big))
        self.assertTrue(any(g.item == "dpkg" and "cut at" in g.reason for g in result.gaps))

    def test_no_package_manager_is_not_applicable(self):
        result = parse(("packages.dpkg", b"", "na", "-", "no /var/lib/dpkg/status"))
        self.assertEqual([(g.item, g.status) for g in result.gaps],
                         [("package manager", Status.NA)])


if __name__ == "__main__":
    unittest.main()
