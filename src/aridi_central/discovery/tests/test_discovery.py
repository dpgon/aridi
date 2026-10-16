"""Authorized networks, the scanner and scan jobs (TODO.md 7.2 and 7.3).

No test connects outside 127.0.0.1: the scanner gets a fake connect that records every
attempt, or a server listening on the loopback.
"""

import ipaddress
import socket
import threading
import time
from unittest import mock

from django.core.exceptions import ValidationError
from django.test import Client, TestCase, TransactionTestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from aridi_central.changes.tests.helpers import snapshot as snapshot_data
from aridi_central.collection.models import Job, Schedule
from aridi_central.collection.worker import Worker, enqueue_scan
from aridi_central.discovery.models import AuthorizedNetwork, ScanResult, validate_cidr
from aridi_central.discovery.scanner import (COMMON_PORTS, OutsidePerimeter, Perimeter,
                                             RateLimit, Scanner)
from aridi_central.discovery.scanning import run_scan
from aridi_central.inventory.models import Machine, Relation, Snapshot
from aridi_central.web import roles
from aridi_central.web.tests.test_web import user_with


class Recorder:
    """A fake connect: records (ip, port) and says OPEN ones are open."""

    def __init__(self, open_=()):
        self.open = set(open_)
        self.attempts = []
        self.lock = threading.Lock()

    def __call__(self, ip, port, timeout):
        with self.lock:
            self.attempts.append((str(ip), port))
        return (str(ip), port) in self.open


def perimeter(*cidrs):
    return Perimeter(lambda: [ipaddress.ip_network(c) for c in cidrs])


class Listener:
    """A TCP server on 127.0.0.1 that accepts and closes."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            conn.close()

    def close(self):
        self.sock.close()


class CidrTest(TestCase):

    def test_valid_and_normalized(self):
        for cidr in ("192.0.2.0/24", "10.0.0.0/16", "192.0.2.7/32", "2001:db8::/112",
                     "2001:db8::1/128"):
            with self.subTest(cidr=cidr):
                validate_cidr(cidr)
        network = AuthorizedNetwork.objects.create(cidr=" 2001:DB8::/120 ", description="x")
        self.assertEqual(network.cidr, "2001:db8::/120")

    def test_invalid_or_too_large(self):
        for cidr in ("not a network", "192.0.2.1/24", "10.0.0.0/15", "0.0.0.0/0",
                     "2001:db8::/64", "224.0.0.0/24", "300.0.0.0/24", "192.0.2.0/33"):
            with self.subTest(cidr=cidr):
                with self.assertRaises(ValidationError):
                    validate_cidr(cidr)

    @override_settings(ARIDI_SCAN_MAX_PREFIX_V4=24)
    def test_maximum_is_configurable(self):
        with self.assertRaises(ValidationError):
            validate_cidr("10.0.0.0/23")
        validate_cidr("10.0.0.0/24")


class ScannerTest(TestCase):

    def test_finds_the_open_ports_of_the_network(self):
        recorder = Recorder({("192.0.2.2", 22), ("192.0.2.1", 443)})
        scanner = Scanner(perimeter("192.0.2.0/30"), rate=10000, connect=recorder)
        found = scanner.scan(ipaddress.ip_network("192.0.2.0/30"), (22, 443))
        self.assertEqual([(str(ip), port) for ip, port in found],
                         [("192.0.2.1", 443), ("192.0.2.2", 22)])
        # The hosts of a /30 are .1 and .2: .3 (broadcast) is not a target.
        self.assertEqual(sorted(recorder.attempts), [("192.0.2.1", 22), ("192.0.2.1", 443),
                                                     ("192.0.2.2", 22), ("192.0.2.2", 443)])

    def test_outside_the_perimeter_no_connection_at_all(self):
        recorder = Recorder()
        scanner = Scanner(perimeter("192.0.2.0/24"), rate=10000, connect=recorder)
        with self.assertRaises(OutsidePerimeter):
            scanner.scan(ipaddress.ip_network("198.51.100.0/30"), COMMON_PORTS)
        self.assertEqual(recorder.attempts, [])
        self.assertGreater(scanner.refused, 0)

    def test_deactivating_stops_the_scan(self):
        networks = [ipaddress.ip_network("192.0.2.0/24")]
        recorder = Recorder()
        scan_perimeter = Perimeter(lambda: list(networks))
        scan_perimeter.REFRESH = 0
        scanner = Scanner(scan_perimeter, rate=10000, threads=1, connect=recorder)

        def connect(ip, port, timeout):
            if len(recorder.attempts) == 10:
                networks.clear()
            return recorder(ip, port, timeout)

        scanner.connect = connect
        with self.assertRaises(OutsidePerimeter):
            scanner.scan(ipaddress.ip_network("192.0.2.0/24"), (22,))
        self.assertLess(len(recorder.attempts), 30)

    def test_a_real_local_server_is_detected(self):
        listener = Listener()
        self.addCleanup(listener.close)
        found = Scanner(perimeter("127.0.0.1/32"), rate=1000, timeout=1).scan(
            ipaddress.ip_network("127.0.0.1/32"), (listener.port, 1))
        self.assertEqual(found, [(ipaddress.ip_address("127.0.0.1"), listener.port)])

    def test_rate_limit(self):
        clock = [0.0]
        slept = []
        limit = RateLimit(10, clock=lambda: clock[0], sleep=slept.append)
        for _ in range(5):
            limit.wait()
        self.assertEqual([round(s, 3) for s in slept], [0.1, 0.2, 0.3, 0.4])
        recorder = Recorder()
        scanner = Scanner(perimeter("192.0.2.0/24"), rate=50, threads=8, connect=recorder)
        start = time.monotonic()
        scanner.scan(ipaddress.ip_network("192.0.2.0/27"), (22,))      # 30 hosts
        elapsed = time.monotonic() - start
        self.assertEqual(len(recorder.attempts), 30)
        self.assertGreaterEqual(elapsed, 29 / 50 - 0.02)


@override_settings(ARIDI_SCAN_ENABLED=True)
class ScanJobTest(TestCase):

    def setUp(self):
        self.network = AuthorizedNetwork.objects.create(cidr="192.0.2.0/30",
                                                        description="test network")

    def job(self):
        return enqueue_scan(self.network)

    @override_settings(ARIDI_SCAN_ENABLED=False)
    def test_disabled_does_not_run(self):
        recorder = Recorder()
        outcome = run_scan(self.job(), connect=recorder)
        self.assertFalse(outcome.ok)
        self.assertIn("disabled", outcome.reason)
        self.assertEqual(recorder.attempts, [])

    def test_inactive_network_does_not_run(self):
        job = self.job()
        AuthorizedNetwork.objects.update(active=False)
        recorder = Recorder()
        self.assertFalse(run_scan(job, connect=recorder).ok)
        self.assertEqual(recorder.attempts, [])
        self.assertIsNone(enqueue_scan(AuthorizedNetwork.objects.get()))

    def test_ips_from_relations_outside_the_perimeter_are_never_touched(self):
        # A machine whose snapshot names 203.0.113.9 in a log, and its own 192.0.2.1.
        machine = Machine.objects.create(name="srv", ssh_target="aridi@192.0.2.1")
        data = snapshot_data()
        data["relations"].append({"ip": "203.0.113.9", "role": "named_in_file",
                                  "source": "carving", "detail": "/var/log/auth.log"})
        snap = Snapshot.objects.create(machine=machine, collected_at=timezone.now(),
                                       origin="ssh", data=data, result="complete")
        Relation.objects.create(snapshot=snap, ip="203.0.113.9", role="named_in_file",
                                source="carving")
        recorder = Recorder({("192.0.2.1", 22)})
        outcome = run_scan(self.job(), connect=recorder)
        self.assertTrue(outcome.ok, outcome.reason)
        touched = {ip for ip, _ in recorder.attempts}
        self.assertEqual(touched, {"192.0.2.1", "192.0.2.2"})
        self.assertNotIn("203.0.113.9", touched)
        # The open port is a result and a relation of the machine's snapshot.
        self.assertEqual(list(ScanResult.objects.values_list("ip", "port", "service")),
                         [("192.0.2.1", 22, "ssh")])
        relation = Relation.objects.get(role="scan_open_port")
        self.assertEqual((relation.snapshot, relation.ip, relation.source),
                         (snap, "192.0.2.1", "scan"))
        self.assertTrue(relation.detail.startswith("tcp/22 ssh, scan of "))

    def test_a_second_scan_replaces_the_relations(self):
        machine = Machine.objects.create(name="srv", ssh_target="aridi@192.0.2.1")
        Snapshot.objects.create(machine=machine, collected_at=timezone.now(), origin="ssh",
                                data=snapshot_data(), result="complete")
        run_scan(self.job(), connect=Recorder({("192.0.2.1", 22)}))
        Job.objects.update(state=Job.State.DONE)
        run_scan(self.job(), connect=Recorder({("192.0.2.1", 22)}))
        self.assertEqual(Relation.objects.filter(role="scan_open_port").count(), 1)
        self.assertEqual(ScanResult.objects.count(), 2)

    def test_one_pending_scan_per_network(self):
        self.assertIsNotNone(self.job())
        self.assertIsNone(self.job())


class ScheduledScanTest(TransactionTestCase):

    @override_settings(ARIDI_SCAN_ENABLED=True)
    def test_scheduled_scan_through_the_worker(self):
        listener = Listener()
        self.addCleanup(listener.close)
        network = AuthorizedNetwork.objects.create(cidr="127.0.0.1/32", description="lo")
        machine = Machine.objects.create(name="local", ssh_target="aridi@127.0.0.1")
        Snapshot.objects.create(machine=machine, collected_at=timezone.now(), origin="ssh",
                                data=snapshot_data(), result="complete")
        schedule = Schedule.objects.create(network=network, kind=Schedule.Kind.INTERVAL,
                                           every_hours=24,
                                           next_run_at=timezone.now())
        worker = Worker()
        with self.settings(ARIDI_SCAN_TIMEOUT=0.5), \
                mock.patch("aridi_central.discovery.scanning.COMMON_PORTS",
                           (listener.port, 1)):
            [job] = worker.due_schedules()
            self.assertEqual((job.kind, job.network, job.origin), ("scan", network, "ssh"))
            worker.run_job(worker.claim(1)[0])
        job.refresh_from_db()
        self.assertEqual(job.state, Job.State.DONE, job.reason)
        schedule.refresh_from_db()
        self.assertGreater(schedule.next_run_at, timezone.now())
        self.assertEqual(list(ScanResult.objects.values_list("ip", "port")),
                         [("127.0.0.1", listener.port)])
        self.assertEqual(job.reason, "1 open port(s)")
        self.assertEqual(Relation.objects.get(role="scan_open_port").snapshot.machine,
                         machine)


@override_settings(SECURE_SSL_REDIRECT=False)
class NetworkWebTest(TestCase):

    @classmethod
    def setUpTestData(cls):
        cls.admin = user_with(roles.ADMIN, "admin")
        cls.reader = user_with(roles.READ_ONLY, "reader")
        cls.network = AuthorizedNetwork.objects.create(cidr="192.0.2.0/24",
                                                       description="lab")

    def client_for(self, user):
        client = Client()
        client.force_login(user)
        return client

    def test_read_only_sees_and_cannot_manage(self):
        client = self.client_for(self.reader)
        for name, args in (("network-list", []), ("network-detail", [self.network.pk])):
            self.assertEqual(client.get(reverse(name, args=args)).status_code, 200)
        for method, name, args in (("get", "network-create", []),
                                   ("post", "network-create", []),
                                   ("post", "network-edit", [self.network.pk]),
                                   ("post", "network-delete", [self.network.pk]),
                                   ("post", "network-scan", [self.network.pk])):
            with self.subTest(view=name, method=method):
                response = getattr(client, method)(reverse(name, args=args),
                                                   {"cidr": "198.51.100.0/24"})
                self.assertEqual(response.status_code, 403)
        self.assertEqual(AuthorizedNetwork.objects.count(), 1)
        self.assertEqual(Job.objects.count(), 0)

    def test_admin_authorizes_with_confirmation(self):
        client = self.client_for(self.admin)
        form = {"cidr": "198.51.100.0/24", "description": "ours", "ports": "common",
                "active": "on"}
        self.assertEqual(client.post(reverse("network-create"), form).status_code, 200)
        self.assertFalse(AuthorizedNetwork.objects.filter(cidr="198.51.100.0/24").exists())
        response = client.post(reverse("network-create"), dict(form, confirm="on"))
        self.assertEqual(response.status_code, 302)
        network = AuthorizedNetwork.objects.get(cidr="198.51.100.0/24")
        self.assertEqual(network.authorized_by, self.admin)
        response = client.post(reverse("network-create"),
                               dict(form, cidr="10.0.0.0/8", confirm="on"))
        self.assertEqual(response.status_code, 200)
        self.assertIn("Too large", response.content.decode())

    def test_scan_now_needs_scanning_enabled(self):
        client = self.client_for(self.admin)
        client.post(reverse("network-scan", args=[self.network.pk]))
        self.assertEqual(Job.objects.count(), 0)
        with self.settings(ARIDI_SCAN_ENABLED=True):
            client.post(reverse("network-scan", args=[self.network.pk]))
        self.assertEqual(Job.objects.get().kind, "scan")
        self.assertEqual(self.client_for(self.reader).get(reverse("job-list")).status_code,
                         200)

    def test_machine_page_shows_scanned_ports(self):
        machine = Machine.objects.create(name="srv", ssh_target="aridi@192.0.2.1")
        Snapshot.objects.create(machine=machine, collected_at=timezone.now(), origin="ssh",
                                data=snapshot_data(), result="complete")
        ScanResult.objects.create(network=self.network, ip="192.0.2.1", port=22,
                                  service="ssh", scanned_at=timezone.now())
        body = self.client_for(self.reader).get(
            reverse("machine-detail", args=[machine.pk])).content.decode()
        self.assertIn("Open ports found by scanning", body)
        self.assertIn("tcp/22", body)

    def test_scan_relations_are_in_the_relation_map(self):
        machine = Machine.objects.create(name="srv", ssh_target="aridi@192.0.2.1")
        snap = Snapshot.objects.create(machine=machine, collected_at=timezone.now(),
                                       origin="ssh", data=snapshot_data(), result="complete")
        Relation.objects.create(snapshot=snap, ip="192.0.2.1", role="scan_open_port",
                                source="scan", detail="tcp/22 ssh, scan of 2026-10-16 10:00 UTC")
        body = self.client_for(self.reader).get(
            reverse("machine-map", args=[machine.pk])).content.decode()
        self.assertIn("scan_open_port", body)
        self.assertIn("tcp/22 ssh, scan of 2026-10-16 10:00 UTC", body)
