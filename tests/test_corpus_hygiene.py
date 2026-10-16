"""The corpus must not carry data of the host that captured it, nor secrets.

Found on 2026-10-15: the Lima VMs mounted the host home directory and created a guest user
with the host user's name, and the container bind mount showed a host temporary path
(tests/corpus/README.md).
"""

import re
import unittest

from tests.helpers import CORPUS, REPO

FILES = sorted(list(CORPUS.glob("*/*/*")) +
               list((REPO / "tests" / "parity").glob("*/*")))

HOST_TRACES = re.compile(rb"/Users/|/var/folders/|/private/var/|/host_mnt/| - (virtiofs|9p) ")
FULL_HASH = re.compile(rb"\$(1|2[aby]|5|6|7|y|gy)\$[./0-9A-Za-z$]{8,}")


class HygieneTest(unittest.TestCase):

    def test_there_are_files(self):
        self.assertGreater(len(FILES), 100)

    def test_no_host_traces(self):
        for path in FILES:
            with self.subTest(path=str(path.relative_to(REPO))):
                match = HOST_TRACES.search(path.read_bytes())
                self.assertIsNone(match, match and match.group())

    def test_no_password_hashes(self):
        for path in FILES:
            with self.subTest(path=str(path.relative_to(REPO))):
                self.assertIsNone(FULL_HASH.search(path.read_bytes()))


if __name__ == "__main__":
    unittest.main()
