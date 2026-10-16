"""Area "users" (src/aridi/parsers/users.py), TODO.md 3.7."""

import re
import unittest

from aridi import bundle
from aridi.interpret import interpret
from aridi.model import Status
from aridi.parsers import users
from tests.helpers import (CORPUS, corpus_bundles, facts, legacy_bundle, legacy_report,
                           make_bundle, sample_name, samples)

# TODO.md 3.7 (d): any string with the shape of a full hash.
FULL_HASH = re.compile(rb"\$[0-9a-z]+\$[^:]{20,}")


def users_of(path):
    return interpret(bundle.read(path)).sections["users"]


def parse(*sections):
    return users.parse(dict(bundle.parse(make_bundle(sections)).sections))


class CorpusTest(unittest.TestCase):

    def test_no_bundle_contains_a_full_hash(self):
        paths = corpus_bundles() + [legacy_bundle("debian12"), legacy_bundle("centos7")]
        for path in paths:
            with self.subTest(bundle=str(path)):
                self.assertIsNone(FULL_HASH.search(path.read_bytes()))

    def test_accounts_and_prefixes_match_facts(self):
        for sample in samples():
            with self.subTest(sample=sample_name(sample)):
                section = users_of(sample / "bundle.aridi")
                ref = facts(sample)
                self.assertEqual(section.status, Status.OK)
                names = [line.split(":")[0] for line in ref["passwd"].splitlines() if line]
                self.assertEqual([u["name"] for u in section.data["users"]], names)
                groups = [line.split(":")[0] for line in ref["group"].splitlines() if line]
                self.assertEqual([g["name"] for g in section.data["groups"]], groups)
                prefixes = dict(line.split(":", 1) for line in ref["shadow_prefixes"].splitlines()
                                if ":" in line)
                by_name = {u["name"]: u for u in section.data["users"]}
                for name, prefix in prefixes.items():
                    got = (by_name[name]["password"], by_name[name]["algorithm"])
                    if prefix == "other":
                        # facts.sh folds every non-hash text into "other"; the collector
                        # tells des, bsdi and invalid apart (test_password_states).
                        self.assertIn(got[0], ("invalid", "locked", "set"), name)
                    else:
                        self.assertEqual(got, users.password_state(prefix), name)

    def test_alice_has_a_password_never_empty(self):
        """docs/MVP.md n.º 12: yescrypt came out as "no password" in 2019."""
        expected = {"debian12": "yescrypt", "debian13": "yescrypt", "ubuntu2404": "yescrypt",
                    "fedora44": "yescrypt", "arch": "yescrypt", "rocky9": "sha512",
                    "centos7": "sha512", "centos6": "sha512", "alpine320": "sha512",
                    "leap156": "sha512"}
        for name, algorithm in expected.items():
            with self.subTest(sample=name):
                alice = next(u for u in users_of(CORPUS / name / "minimal" / "bundle.aridi")
                             .data["users"] if u["name"] == "alice")
                self.assertEqual((alice["password"], alice["algorithm"]), ("set", algorithm))

    def test_locked_bob_and_orphan_member(self):
        for sample in samples():
            with self.subTest(sample=sample_name(sample)):
                data = users_of(sample / "bundle.aridi").data
                bob = next(u for u in data["users"] if u["name"] == "bob")
                # Ground truth from facts.txt: Alpine's "adduser -D" already locks ("!"),
                # even though the scenario could not run "passwd -l".
                prefix = dict(line.split(":", 1) for line in
                              facts(sample)["shadow_prefixes"].splitlines())["bob"]
                self.assertTrue(prefix.startswith(("!", "*")))
                self.assertEqual(bob["password"], "locked")
                self.assertIn({"group": "ghostgrp", "member": "ghostuser"},
                              data["members_without_account"])
                alice = next(u for u in data["users"] if u["name"] == "alice")
                self.assertIn("ghostgrp", alice["groups"])

    def test_alpine_kvm_member_without_account(self):
        data = users_of(CORPUS / "alpine320" / "minimal" / "bundle.aridi").data
        self.assertIn({"group": "kvm", "member": "kvm"}, data["members_without_account"])


class LegacyRegressionTest(unittest.TestCase):

    def test_debian12_users_and_groups_like_legacy(self):
        for distro in ("debian12", "centos7"):
            with self.subTest(distro=distro):
                match = re.search(r"There are (\d+) users, .* and (\d+) groups",
                                  legacy_report(distro))
                data = users_of(legacy_bundle(distro)).data
                self.assertEqual((len(data["users"]), len(data["groups"])),
                                 (int(match.group(1)), int(match.group(2))))
        match = re.search(r"There are (\d+) users, .* and (\d+) groups",
                          legacy_report("debian12"))
        self.assertEqual(match.groups(), ("18", "38"))


class SyntheticTest(unittest.TestCase):

    def test_password_states(self):
        cases = {"$y$": ("set", "yescrypt"), "$1$": ("set", "md5"), "$2b$": ("set", "bcrypt"),
                 "$5$": ("set", "sha256"), "$6$": ("set", "sha512"),
                 "$gy$": ("set", "gost-yescrypt"), "$7$": ("set", "scrypt"),
                 "!$6$": ("locked", "sha512"), "!": ("locked", None), "!!": ("locked", None),
                 "*": ("locked", None), "": ("empty", None), "other": ("invalid", None),
                 "!other": ("locked", None), "des": ("set", "des"), "bsdi": ("set", "bsdi-des"),
                 "$zz$": ("set", "unknown"), None: ("unknown", None)}
        for prefix, expected in cases.items():
            with self.subTest(prefix=prefix):
                self.assertEqual(users.password_state(prefix), expected)

    def test_algorithm_counts_including_md5(self):
        """The MD5 counter of 2019 was always 0."""
        passwd = b"a:x:1:1::/:/bin/sh\nb:x:2:2::/:/bin/sh\nc:x:3:3::/:/bin/sh\n"
        shadow = b"a:$1$:1::::::\nb:$1$:1::::::\nc:$6$:1::::::\n"
        data = parse(("users.passwd", passwd), ("users.shadow", shadow)).data
        self.assertEqual(data["algorithms"], {"md5": 2, "sha512": 1})

    def test_shadow_denied(self):
        result = parse(("users.passwd", b"root:x:0:0:root:/root:/bin/sh\n"),
                       ("users.shadow", b"", "denied", "-", "not readable: /etc/shadow"))
        self.assertEqual(result.data["users"][0]["password"], "unknown")
        self.assertFalse(result.data["shadow_read"])
        self.assertEqual({g.item: g.status for g in result.gaps}["password state"],
                         Status.DENIED)

    def test_password_in_passwd_and_empty_field(self):
        passwd = b"old:$6$:5:5::/:/bin/sh\nopen::6:6::/:/bin/sh\n"
        data = parse(("users.passwd", passwd), ("users.shadow", b"")).data
        self.assertEqual([(u["password"], u["algorithm"]) for u in data["users"]],
                         [("set", "sha512"), ("empty", None)])

    def test_unknown_algorithm_is_declared(self):
        result = parse(("users.passwd", b"x1:x:1:1::/:/bin/sh\n"),
                       ("users.shadow", b"x1:$zz$:1::::::\n"))
        self.assertIn("password algorithm", [g.item for g in result.gaps])

    def test_uid_without_group_and_malformed_lines(self):
        passwd = b"u:x:10:999::/home/u:/bin/sh\nbroken line\n"
        group = b"g:x:5:u\n:x:6:\n"
        data = parse(("users.passwd", passwd), ("users.group", group)).data
        self.assertEqual(len(data["users"]), 1)
        self.assertTrue(data["users"][0]["primary_group_missing"])
        self.assertEqual(data["users"][0]["groups"], ["g"])


if __name__ == "__main__":
    unittest.main()
