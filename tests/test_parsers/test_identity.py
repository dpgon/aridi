"""Area "identity" (src/aridi/parsers/identity.py), TODO.md 3.6."""

import re
import unittest

from aridi import bundle
from aridi.interpret import interpret
from aridi.model import Status
from aridi.parsers import identity
from aridi.views import text
from tests.helpers import (CORPUS, facts, legacy_bundle, legacy_report, make_bundle,
                           sample_name, samples)


def snapshot_of(path):
    return interpret(bundle.read(path))


def parse(*sections):
    return identity.parse(dict(bundle.parse(make_bundle(sections)).sections))


class CorpusTest(unittest.TestCase):

    def test_hostname_and_banner_in_every_sample(self):
        for sample in samples():
            with self.subTest(sample=sample_name(sample)):
                section = snapshot_of(sample / "bundle.aridi").sections["identity"]
                self.assertEqual(section.status, Status.OK)
                self.assertEqual(section.data["hostname"], facts(sample)["hostname"].strip())
                banner = section.data["banners"]["/etc/issue.net"]["text"]
                self.assertIn("\x1b[31m", banner)          # kept as received
                self.assertTrue(section.data["hostid"])
                # No sample has a DNS domain. Where the hostname resolves, dnsdomainname
                # exits 0 and the domain is ""; where it does not, the domain is unknown.
                raw = bundle.read(sample / "bundle.aridi").section("identity.dnsdomainname")
                if raw.rc == 0:
                    self.assertEqual(section.data["dns_domain"], "")
                    self.assertEqual(section.gaps, [])
                else:
                    self.assertIsNone(section.data["dns_domain"])
                    self.assertEqual([g.item for g in section.gaps], ["dns domain"])

    def test_banner_neutralized_in_the_text_view(self):
        report = text.render(snapshot_of(CORPUS / "debian12" / "minimal" / "bundle.aridi"),
                             detail=True)
        self.assertNotIn("\x1b", report)
        self.assertIn("| Corpus banner \\x1b[31mred\\x1b[0m <script>alert(1)</script>", report)


class LegacyRegressionTest(unittest.TestCase):

    def test_same_hostname_as_legacy(self):
        for distro in ("debian12", "centos7"):
            with self.subTest(distro=distro):
                legacy = re.search(r"\|__hostname: (\S+)", legacy_report(distro)).group(1)
                data = snapshot_of(legacy_bundle(distro)).sections["identity"].data
                self.assertEqual(data["hostname"], legacy)


class SyntheticTest(unittest.TestCase):

    def test_domain_configured_empty_and_unknown(self):
        def domain(*sections):
            return parse(*sections).data["dns_domain"]

        self.assertEqual(domain(("identity.dnsdomainname", b"example.org\n")), "example.org")
        self.assertEqual(domain(("identity.dnsdomainname", b"\n")), "")
        result = parse(("identity.dnsdomainname", b"", "ok", 1,
                        "dnsdomainname: Temporary failure in name resolution"))
        self.assertIsNone(result.data["dns_domain"])
        self.assertEqual({g.item: g.status for g in result.gaps}["dns domain"], Status.NA)
        result = parse(("identity.dnsdomainname", b"", "missing", "-", "tool not found"))
        self.assertEqual({g.item: g.status for g in result.gaps}["dns domain"], Status.MISSING)

    def test_domain_is_not_the_hostname(self):
        """2019 gathering2.py:35 showed the hostname as the domain."""
        data = parse(("identity.kernel_hostname", b"web1\n"),
                     ("identity.dnsdomainname", b"example.org\n")).data
        self.assertEqual((data["hostname"], data["dns_domain"]), ("web1", "example.org"))

    def test_nis_none_and_motd_d(self):
        motd_d = b"==> /etc/motd.d/10-a <==\nhello\n\n==> /etc/motd.d/20-b <==\nbye\n\n"
        data = parse(("identity.nis_domainname", b"(none)\n"),
                     ("identity.motd_d", motd_d)).data
        self.assertIsNone(data["nis_domain"])
        self.assertEqual(data["banners"]["/etc/motd.d/10-a"]["text"], "hello\n")
        self.assertEqual(data["banners"]["/etc/motd.d/20-b"]["text"], "bye\n")

    def test_unreadable_banner_is_a_gap(self):
        result = parse(("identity.motd", b"", "denied", "-", "not readable: /etc/motd"))
        self.assertEqual({g.item: g.status for g in result.gaps}["banner /etc/motd"],
                         Status.DENIED)


if __name__ == "__main__":
    unittest.main()
