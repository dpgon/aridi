import io
import unittest
from contextlib import redirect_stderr

import aridi
from aridi import cli


class SmokeTest(unittest.TestCase):

    def test_version(self):
        self.assertEqual(aridi.__version__, "2.0.0.dev0")
        self.assertEqual(aridi.BUNDLE_FORMAT_VERSION, 1)

    def test_subcommands_not_implemented_yet(self):
        for command in ("report", "interpret", "validate"):
            with self.subTest(command=command), redirect_stderr(io.StringIO()) as err:
                self.assertEqual(cli.main([command, "some.aridi"]), cli.EXIT_FAILED)
                self.assertIn("not implemented", err.getvalue())

    def test_command_is_required(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as ctx:
            cli.main([])
        self.assertEqual(ctx.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
