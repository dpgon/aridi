"""Project settings (TODO.md 5.1): environment, SQLite pragmas and deploy checks."""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

from django.test import SimpleTestCase

from aridi_central.testing import REPO

MANAGE = str(REPO / "src" / "aridi_central" / "manage.py")
PRODUCTION = {"ARIDI_SECRET_KEY": "test-only-0123456789abcdefghijklmnopqrstuvwxyz-ABCDEFGH",
              "ARIDI_ALLOWED_HOSTS": "aridi.example"}


def manage(*args, env=None):
    clean = {k: v for k, v in os.environ.items() if not k.startswith("ARIDI_")}
    clean.update(env or {})
    return subprocess.run([sys.executable, MANAGE, *args], env=clean, capture_output=True,
                          text=True, timeout=120)


class SettingsTest(SimpleTestCase):

    def test_production_without_secret_key_fails(self):
        result = manage("check", env={"ARIDI_DB_PATH": "/tmp/unused.db"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ARIDI_SECRET_KEY is not set", result.stderr)

    def test_minimal_variables_and_wal(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(PRODUCTION, ARIDI_DB_PATH=str(Path(tmp) / "aridi.db"))
            self.assertEqual(manage("migrate", "-v0", env=env).returncode, 0)
            result = manage("shell", "-v0", "-c",
                            "from django.db import connection\n"
                            "c = connection.cursor()\n"
                            "print(c.execute('PRAGMA journal_mode').fetchone()[0],"
                            " c.execute('PRAGMA foreign_keys').fetchone()[0],"
                            " c.execute('PRAGMA busy_timeout').fetchone()[0])", env=env)
            self.assertEqual(result.stdout.split(), ["wal", "1", "20000"], result.stderr)

    def test_check_deploy_without_issues(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(PRODUCTION, ARIDI_DB_PATH=str(Path(tmp) / "aridi.db"))
            result = manage("check", "--deploy", "--fail-level", "WARNING", env=env)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            self.assertIn("no issues", result.stdout)

    def test_migrations_are_up_to_date(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(PRODUCTION, ARIDI_DB_PATH=str(Path(tmp) / "aridi.db"))
            result = manage("makemigrations", "--check", "--dry-run", env=env)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
