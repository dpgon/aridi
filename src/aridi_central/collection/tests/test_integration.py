"""Real SSH collection from a disposable container (TODO.md 5.4), and the scan of that
container from an authorized network (acceptance of phase 7).

Runs only when tests/central/run.sh starts the target (tests/central/ssh-target.sh) and
sets ARIDI_TEST_SSH_HOST; otherwise it is skipped.
"""

import os
import socket
import unittest

from django.contrib.auth.models import User
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from aridi_central.collection import ssh
from aridi_central.collection.models import Job, Schedule
from aridi_central.collection.worker import Worker, enqueue
from aridi_central.discovery.models import AuthorizedNetwork
from aridi_central.inventory.importing import collector_sha256
from aridi_central.inventory.models import Machine, Relation, Snapshot

HOST = os.environ.get("ARIDI_TEST_SSH_HOST", "")


@unittest.skipUnless(HOST, "no SSH target (tests/central/run.sh starts one)")
@override_settings(ARIDI_SSH_CONFIG="/k/ssh_config", ARIDI_KNOWN_HOSTS="/k/known_hosts")
class SshIntegrationTest(TestCase):

    def machine(self, user, privilege=Machine.Privilege.SUDO):
        return Machine.objects.create(name=f"{user}-{privilege}", ssh_target=f"{user}@{HOST}",
                                      privilege=privilege)

    def test_sudo_with_the_installed_script(self):
        machine = self.machine("aridi")
        [job] = enqueue([machine])
        worker = Worker()
        worker.run_job(worker.claim(1)[0])
        job.refresh_from_db()
        self.assertEqual(job.state, Job.State.DONE, job.reason)
        snapshot = job.snapshot
        self.assertIn(snapshot.result, (Snapshot.Result.COMPLETE, Snapshot.Result.GAPS))
        self.assertEqual(snapshot.installed_collector_sha256, collector_sha256())
        self.assertFalse(snapshot.collector_outdated)
        # Root could read /etc/shadow: no "denied" there.
        self.assertTrue(snapshot.data["sections"]["users"]["data"]["shadow_read"])
        self.assertEqual(snapshot.data["machine"]["hostname"], HOST)

    def test_user_mode_through_stdin(self):
        result = ssh.collect(self.machine("nosudo", Machine.Privilege.USER))
        self.assertTrue(result.ok, result.reason)
        self.assertEqual(result.installed_sha256, "")
        from aridi_central.inventory.importing import parse
        core = parse(result.bundle)
        self.assertFalse(core.sections["users"].data["shadow_read"])
        self.assertEqual(core.outcome().value, "gaps")

    def test_account_without_sudo_rule(self):
        result = ssh.collect(self.machine("nosudo"))
        self.assertFalse(result.ok)
        self.assertIn("sudo denied", result.reason)

    @override_settings(ARIDI_KNOWN_HOSTS="/dev/null")
    def test_unknown_host_key(self):
        result = ssh.collect(self.machine("aridi"))
        self.assertFalse(result.ok)
        self.assertIn("host key", result.reason)

    def test_no_connection(self):
        machine = Machine.objects.create(name="nowhere", ssh_target="aridi@nonexistent.invalid")
        result = ssh.collect(machine)
        self.assertFalse(result.ok)
        self.assertIn("not resolved", result.reason)

    @override_settings(ARIDI_SCAN_ENABLED=True, SECURE_SSL_REDIRECT=False)
    def test_scheduled_scan_finds_port_22_and_shows_it(self):
        """Acceptance of phase 7: an authorized network with the SSH test machine."""
        machine = self.machine("aridi")
        worker = Worker()
        enqueue([machine])
        worker.run_job(worker.claim(1)[0])
        ip = socket.gethostbyname(HOST)
        self.assertTrue(Relation.objects.filter(snapshot=machine.latest_snapshot(),
                                                role="local", ip=ip).exists())
        network = AuthorizedNetwork.objects.create(cidr=f"{ip}/32", description="SSH target")
        Schedule.objects.create(network=network, kind=Schedule.Kind.INTERVAL, every_hours=24,
                                next_run_at=timezone.now())
        [job] = worker.due_schedules()
        worker.run_job(worker.claim(1)[0])
        job.refresh_from_db()
        self.assertEqual(job.state, Job.State.DONE, job.reason)
        self.assertEqual(list(network.results.values_list("ip", "port", "service")),
                         [(ip, 22, "ssh")])
        client = Client()
        client.force_login(User.objects.create_superuser("root", password="x" * 16))
        body = client.get(reverse("machine-detail", args=[machine.pk])).content.decode()
        self.assertIn("Open ports found by scanning", body)
        self.assertIn(f"<td>{ip}</td><td>tcp/22</td><td>ssh</td>", body)
