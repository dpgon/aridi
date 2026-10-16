import io
import unittest
from contextlib import redirect_stderr

import aridi
from aridi import cli


class SmokeTest(unittest.TestCase):

    def test_version(self):
        self.assertEqual(aridi.__version__, "2.0.0")
        self.assertEqual(aridi.BUNDLE_FORMAT_VERSION, 1)

    def test_bundle_format_matches_reader_and_collector(self):
        from aridi import bundle
        from tests.helpers import REPO
        self.assertEqual(bundle.FORMAT_VERSION, aridi.BUNDLE_FORMAT_VERSION)
        script = (REPO / "collector" / "aridi-collect.sh").read_text(encoding="utf-8")
        self.assertIn(f"ARIDI_BUNDLE_FORMAT={aridi.BUNDLE_FORMAT_VERSION}\n", script)
        self.assertIn(f'ARIDI_COLLECTOR_VERSION="{aridi.__version__}"', script)

    def test_command_is_required(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as ctx:
            cli.main([])
        self.assertEqual(ctx.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
