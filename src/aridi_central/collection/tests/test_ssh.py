"""SSH collection with a fake ssh in PATH (TODO.md 5.4)."""

import hashlib
import os
import stat
import tempfile
from pathlib import Path
from unittest import mock

from django.test import TestCase, override_settings

from aridi_central.collection import ssh
from aridi_central.inventory.models import Machine
from aridi_central.testing import CORPUS, REPO

SCRIPT = REPO / "collector" / "aridi-collect.sh"
BUNDLE = CORPUS / "debian12" / "minimal" / "bundle.aridi"

# Fake ssh: records its arguments and stdin, then behaves as FAKE_SSH_MODE says.
FAKE_SSH = r"""#!/bin/sh
printf '%s\n' "$@" > "$FAKE_SSH_DIR/argv"
cat > "$FAKE_SSH_DIR/stdin"
case $FAKE_SSH_MODE in
    bundle)  echo "$FAKE_SSH_SHA  /usr/local/libexec/aridi-collect.sh" >&2
             cat "$FAKE_SSH_BUNDLE" ;;
    hostkey) echo "Host key verification failed." >&2; exit 255 ;;
    sudo)    echo "sudo: a password is required" >&2; exit 1 ;;
    missing) echo "sudo: /usr/local/libexec/aridi-collect.sh: command not found" >&2
             exit 1 ;;
    sleep)   exec sleep 30 ;;
    flood)   exec yes aridi ;;
esac
"""


class FakeSsh:
    def __init__(self, mode, sha="0" * 64):
        self.dir = tempfile.TemporaryDirectory()
        self.path = Path(self.dir.name) / "ssh"
        self.path.write_text(FAKE_SSH)
        self.path.chmod(self.path.stat().st_mode | stat.S_IXUSR)
        self.env = mock.patch.dict(os.environ, {"FAKE_SSH_DIR": self.dir.name,
                                                "FAKE_SSH_MODE": mode, "FAKE_SSH_SHA": sha,
                                                "FAKE_SSH_BUNDLE": str(BUNDLE)})

    def __enter__(self):
        self.env.start()
        return self

    def __exit__(self, *exc):
        self.env.stop()
        self.dir.cleanup()

    def argv(self):
        return (Path(self.dir.name) / "argv").read_text().splitlines()

    def stdin(self):
        return (Path(self.dir.name) / "stdin").read_bytes()


def machine(**fields):
    defaults = {"name": "m", "ssh_target": "aridi@host.example", "ssh_port": 2222}
    defaults.update(fields)
    return Machine(**defaults)


@override_settings(ARIDI_COLLECTOR_SCRIPT=str(SCRIPT), ARIDI_SSH_CONFIG="",
                   ARIDI_KNOWN_HOSTS="/etc/aridi/known_hosts")
class SshTest(TestCase):

    def test_arguments_sudo_mode(self):
        argv = ssh.build_command(machine(proxy_jump="jump@bastion:22"))
        self.assertEqual(argv[0], "ssh")
        for option in ("BatchMode=yes", "StrictHostKeyChecking=yes",
                       "UserKnownHostsFile=/etc/aridi/known_hosts"):
            self.assertIn(option, argv)
        self.assertEqual(argv[argv.index("-p") + 1], "2222")
        self.assertEqual(argv[argv.index("-J") + 1], "jump@bastion:22")
        self.assertEqual(argv[-3:], ["--", "aridi@host.example", ssh.REMOTE_SUDO])
        self.assertIn("exec sudo -n /usr/local/libexec/aridi-collect.sh", ssh.REMOTE_SUDO)

    def test_injection_is_rejected(self):
        for fields in ({"ssh_target": "-oProxyCommand=touch /tmp/x"},
                       {"ssh_target": "aridi@host;id"},
                       {"ssh_target": "aridi@host -oProxyCommand=x"},
                       {"proxy_jump": "-oProxyCommand=x"},
                       {"ssh_target": ""}):
            with self.subTest(fields=fields):
                with self.assertRaises(ValueError):
                    ssh.build_command(machine(**fields))
                result = ssh.collect(machine(**fields), ssh="/nonexistent/ssh")
                self.assertFalse(result.ok)
                self.assertIn("invalid", result.reason)

    def test_sudo_mode_collects_and_reads_the_installed_hash(self):
        digest = hashlib.sha256(SCRIPT.read_bytes()).hexdigest()
        with FakeSsh("bundle", sha=digest) as fake:
            result = ssh.collect(machine(), ssh=str(fake.path))
            self.assertTrue(result.ok, result.reason)
            self.assertEqual(result.bundle, BUNDLE.read_bytes())
            self.assertEqual(result.installed_sha256, digest)
            self.assertEqual(fake.stdin(), b"")          # nothing sent: script installed
            self.assertEqual(fake.argv()[-1], ssh.REMOTE_SUDO)

    def test_user_mode_sends_the_script_on_stdin(self):
        with FakeSsh("bundle") as fake:
            result = ssh.collect(machine(privilege=Machine.Privilege.USER),
                                 ssh=str(fake.path))
            self.assertTrue(result.ok, result.reason)
            self.assertEqual(fake.stdin(), SCRIPT.read_bytes())
            self.assertEqual(fake.argv()[-1], "exec sh -s")

    def test_failures_have_a_reason(self):
        for mode, reason in (("hostkey", "unknown or changed host key"),
                             ("sudo", "sudo denied"),
                             ("missing", "not installed")):
            with self.subTest(mode=mode), FakeSsh(mode) as fake:
                result = ssh.collect(machine(), ssh=str(fake.path))
                self.assertFalse(result.ok)
                self.assertIn(reason, result.reason)

    def test_timeout(self):
        with FakeSsh("sleep") as fake:
            result = ssh.collect(machine(), ssh=str(fake.path), timeout=1)
            self.assertFalse(result.ok)
            self.assertIn("timed out after 1 s", result.reason)

    def test_output_limit(self):
        with FakeSsh("flood") as fake:
            result = ssh.collect(machine(), ssh=str(fake.path), max_bytes=100_000)
            self.assertFalse(result.ok)
            self.assertIn("larger than 100000 bytes", result.reason)
            self.assertEqual(result.bundle, b"")
