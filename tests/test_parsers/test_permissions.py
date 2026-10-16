"""Area "permissions" (src/aridi/parsers/permissions.py), TODO.md 3.5."""

import re
import unittest

from aridi import bundle
from aridi.interpret import interpret
from aridi.model import Status
from aridi.parsers import permissions
from tests.helpers import (CORPUS, facts, legacy_bundle, legacy_report, make_bundle,
                           sample_name, samples)


def permissions_of(path):
    return interpret(bundle.read(path)).sections["permissions"]


def parse(*sections):
    return permissions.parse(dict(bundle.parse(make_bundle(sections)).sections))


def paths(items):
    return sorted(item["path"] for item in items)


class CorpusTest(unittest.TestCase):

    def test_same_files_as_find_in_facts(self):
        for sample in samples():
            with self.subTest(sample=sample_name(sample)):
                section = permissions_of(sample / "bundle.aridi")
                ref = facts(sample)
                self.assertEqual(section.status, Status.OK)
                self.assertEqual(section.gaps, [])
                data = section.data
                self.assertEqual(paths(data["suid"]), sorted(ref["suid_files"].split()))
                self.assertEqual(paths(data["sgid"]), sorted(ref["sgid_files"].split()))
                self.assertEqual(paths(data["world_writable_dirs_no_sticky"]),
                                 sorted(ref["world_writable_dirs_no_sticky"].split()))

    def test_scenario_files_appear(self):
        for sample in samples():
            with self.subTest(sample=sample_name(sample)):
                data = permissions_of(sample / "bundle.aridi").data
                suid = {item["path"]: item for item in data["suid"]}
                self.assertTrue(suid["/usr/local/bin/aridi-suid-test"]["root_owned"])
                self.assertEqual(suid["/usr/local/bin/aridi-suid-test"]["mode"], "4755")
                self.assertIn("/srv/world-writable", paths(data["world_writable_dirs_no_sticky"]))
                self.assertGreater(data["world_writable_dirs_sticky"], 0)   # /tmp

    def test_account_files(self):
        files = {f["path"]: f for f in
                 permissions_of(CORPUS / "debian12" / "minimal" / "bundle.aridi").data[
                     "account_files"]}
        self.assertEqual(sorted(files), ["/etc/group", "/etc/gshadow", "/etc/passwd",
                                         "/etc/shadow"])
        self.assertFalse(files["/etc/passwd"]["too_open"])
        # Debian ships /etc/shadow as 0640 root:shadow: more open than the recommended 0400.
        self.assertEqual(files["/etc/shadow"]["mode"], "0640")
        self.assertTrue(files["/etc/shadow"]["too_open"])
        rocky = {f["path"]: f for f in
                 permissions_of(CORPUS / "rocky9" / "minimal" / "bundle.aridi").data[
                     "account_files"]}
        self.assertEqual(rocky["/etc/shadow"]["mode"], "0000")
        self.assertFalse(rocky["/etc/shadow"]["too_open"])

    def test_alpine_has_no_gshadow(self):
        files = permissions_of(CORPUS / "alpine320" / "minimal" / "bundle.aridi").data[
            "account_files"]
        self.assertNotIn("/etc/gshadow", [f["path"] for f in files])


class LegacyRegressionTest(unittest.TestCase):

    def test_suid_count_against_legacy(self):
        """2019 followed symbolic links: /usr/bin/sg -> newgrp counted as a second file.

        In the reference container of Debian 12, 2019 found 9 SUID files and the new search
        finds 8. The phase 3 note blamed another mount; the file by file comparison of phase
        4 (tests/test_parity.py) showed it is the link.
        """
        legacy = {}
        for distro in ("debian12", "centos7"):
            report = legacy_report(distro)
            legacy[distro] = int(re.search(r"SUID: Found (\d+) files", report).group(1))
        new = {distro: len(permissions_of(legacy_bundle(distro)).data["suid"])
               for distro in legacy}
        self.assertEqual(legacy["debian12"], 9)
        self.assertEqual(new["debian12"], 8)
        self.assertLessEqual(new["centos7"], legacy["centos7"])


class SyntheticTest(unittest.TestCase):

    FIND = (b"89ed 0 0 /usr/bin/passwd\n"
            b"89ed 1000 1000 /home/u/suid by user\n"
            b"85ed 0 42 /usr/bin/chage\n"
            b"43ff 0 0 /tmp\n"
            b"41ff 0 0 /srv/open\n"
            b"81b6 0 0 /etc/oops\n"
            b"45fd 0 50 /var/local\n"
            b"garbage line\n")

    def test_classification(self):
        data = parse(("permissions.find", self.FIND)).data
        self.assertEqual(paths(data["suid"]), ["/home/u/suid by user", "/usr/bin/passwd"])
        self.assertEqual([f["root_owned"] for f in data["suid"]], [True, False])
        self.assertEqual(paths(data["sgid"]), ["/usr/bin/chage"])
        self.assertEqual(paths(data["world_writable_files"]), ["/etc/oops"])
        self.assertEqual(paths(data["world_writable_dirs_no_sticky"]), ["/srv/open"])
        self.assertEqual(data["world_writable_dirs_sticky"], 1)

    def test_timeout_keeps_a_partial_result(self):
        result = parse(("permissions.find", self.FIND, "timeout", 124, "Terminated"),
                       ("permissions.account_files", b"81a4 0 0 /etc/passwd\n"))
        self.assertEqual(result.status, Status.TIMEOUT)
        self.assertIn("partial result", result.reason)
        self.assertEqual(len(result.data["suid"]), 2)

    def test_search_not_possible_is_a_gap(self):
        result = parse(("permissions.find", b"", "missing", "-", "tool not found: find"))
        self.assertEqual(result.status, Status.OK)
        self.assertFalse(result.data["searched"])
        self.assertEqual({g.item: g.status for g in result.gaps},
                         {"search": Status.MISSING, "account files": Status.ERROR})

    def test_account_files_recommended_modes(self):
        content = (b"81a4 0 0 /etc/passwd\n81b6 0 0 /etc/group\n"
                   b"8100 0 0 /etc/shadow\n8000 0 0 /etc/gshadow\n")
        files = {f["path"]: f["too_open"] for f in permissions.account_files(content.decode())}
        self.assertEqual(files, {"/etc/passwd": False, "/etc/group": True,
                                 "/etc/shadow": False, "/etc/gshadow": False})


if __name__ == "__main__":
    unittest.main()
