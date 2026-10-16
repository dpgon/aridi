"""Queue, worker and schedules (TODO.md 5.5)."""

import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
from datetime import time as clock
from datetime import timedelta
from pathlib import Path

from django.db import connection
from django.test import TestCase, TransactionTestCase
from django.utils import timezone

from aridi_central.collection.models import Job, Schedule
from aridi_central.collection.ssh import Result
from aridi_central.collection.worker import Worker, enqueue
from aridi_central.inventory.models import Group, Machine, Snapshot
from aridi_central.testing import CORPUS, REPO

BUNDLE = (CORPUS / "debian12" / "minimal" / "bundle.aridi").read_bytes()


def machines(count, **fields):
    return [Machine.objects.create(name=f"m{n}", ssh_target=f"aridi@m{n}", **fields)
            for n in range(count)]


def ok_collect(machine):
    return Result(True, bundle=BUNDLE)


class JobTest(TestCase):

    def test_enqueue_skips_pending_inactive_and_import_only(self):
        active, inactive = machines(2)
        inactive.active = False
        inactive.save()
        imported = Machine.objects.create(name="imported")
        self.assertEqual(len(enqueue([active, inactive, imported])), 1)
        self.assertEqual(enqueue([active]), [])          # already queued

    def test_success_stores_the_snapshot(self):
        [machine] = machines(1)
        [job] = enqueue([machine])
        worker = Worker(collect=ok_collect)
        [taken] = worker.claim(5)
        worker.run_job(taken)
        job.refresh_from_db()
        self.assertEqual(job.state, Job.State.DONE)
        self.assertEqual(job.snapshot.result, Snapshot.Result.COMPLETE)
        self.assertEqual(job.snapshot.origin, Snapshot.Origin.ON_DEMAND)

    def test_retry_then_failed_snapshot(self):
        [machine] = machines(1)
        [job] = enqueue([machine])
        job.max_attempts = 2
        job.save()
        worker = Worker(collect=lambda m: Result(False, reason="connection refused"))
        worker.run_job(worker.claim(1)[0])
        job.refresh_from_db()
        self.assertEqual(job.state, Job.State.QUEUED)
        self.assertGreater(job.not_before, timezone.now())
        self.assertEqual(worker.claim(1), [])            # waits for its backoff
        Job.objects.filter(id=job.id).update(not_before=None)
        worker.run_job(worker.claim(1)[0])
        job.refresh_from_db()
        self.assertEqual(job.state, Job.State.FAILED)
        self.assertEqual(job.snapshot.result, Snapshot.Result.FAILED)
        self.assertEqual(job.snapshot.failure_reason, "connection refused")

    def test_invalid_bundle_is_a_failure(self):
        [machine] = machines(1)
        [job] = enqueue([machine])
        job.max_attempts = 1
        job.save()
        worker = Worker(collect=lambda m: Result(True, bundle=b"garbage"))
        worker.run_job(worker.claim(1)[0])
        job.refresh_from_db()
        self.assertEqual(job.state, Job.State.FAILED)
        self.assertIn("invalid bundle", job.reason)


class ScheduleTest(TestCase):

    def test_one_job_per_period(self):
        [machine] = machines(1)
        now = timezone.now()
        schedule = Schedule.objects.create(machine=machine, kind=Schedule.Kind.INTERVAL,
                                           every_hours=6,
                                           next_run_at=now - timedelta(hours=20))
        first, second = Worker(name="a"), Worker(name="b")
        self.assertEqual(len(first.due_schedules()), 1)  # three periods missed: one job
        self.assertEqual(second.due_schedules(), [])
        self.assertEqual(Job.objects.count(), 1)
        schedule.refresh_from_db()
        self.assertGreater(schedule.next_run_at, now)
        self.assertLessEqual(schedule.next_run_at, now + timedelta(hours=6))

    def test_new_schedule_waits_for_its_first_period(self):
        [machine] = machines(1)
        schedule = Schedule.objects.create(machine=machine, kind=Schedule.Kind.DAILY,
                                           daily_at=clock(3, 0))
        self.assertEqual(Worker().due_schedules(), [])
        schedule.refresh_from_db()
        self.assertEqual((schedule.next_run_at.hour, schedule.next_run_at.minute), (3, 0))
        self.assertGreater(schedule.next_run_at, timezone.now())

    def test_group_schedule_skips_machines_with_their_own(self):
        own, other = machines(2)
        group = Group.objects.create(name="g")
        group.machines.add(own, other)
        Schedule.objects.create(machine=own, kind=Schedule.Kind.DAILY, daily_at=clock(1, 0))
        Schedule.objects.create(group=group, kind=Schedule.Kind.INTERVAL, every_hours=1,
                                next_run_at=timezone.now() - timedelta(minutes=1))
        jobs = Worker().due_schedules()
        self.assertEqual([job.machine for job in jobs], [other])
        self.assertEqual(jobs[0].origin, Snapshot.Origin.SSH)


class ConcurrencyTest(TransactionTestCase):

    def test_two_workers_never_take_the_same_job(self):
        enqueue(machines(30))
        taken = {"a": [], "b": []}
        start = threading.Barrier(2)

        def take(name):
            worker = Worker(name=name)
            start.wait()
            while jobs := worker.claim(3):
                taken[name] += [job.id for job in jobs]
            connection.close()

        threads = [threading.Thread(target=take, args=(n,)) for n in taken]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertFalse(set(taken["a"]) & set(taken["b"]))
        self.assertEqual(len(taken["a"]) + len(taken["b"]), 30)
        self.assertEqual(Job.objects.filter(state=Job.State.RUNNING).count(), 30)

    def test_concurrency_limit(self):
        enqueue(machines(6))

        def slow(machine):
            time.sleep(0.3)
            return Result(True, bundle=BUNDLE)

        worker = Worker(max_ssh=2, collect=slow)
        deadline = time.monotonic() + 30
        while Job.objects.exclude(state=Job.State.DONE).exists():
            self.assertLess(time.monotonic(), deadline)
            failed = Job.objects.filter(state=Job.State.FAILED).first()
            self.assertIsNone(failed, failed and failed.reason)
            worker.dispatch()
            time.sleep(0.05)
        self.assertEqual(worker.max_running, 2)

    def test_stop_leaves_no_job_running(self):
        enqueue(machines(3))
        release = threading.Event()

        def stuck(machine):
            release.wait(20)
            return Result(False, reason="killed")

        worker = Worker(max_ssh=3, poll_seconds=0.05, collect=stuck, shutdown_grace=0.2)
        loop = threading.Thread(target=worker.run_forever)
        loop.start()
        deadline = time.monotonic() + 10
        while Job.objects.filter(state=Job.State.RUNNING).count() < 3:
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.05)
        worker.stop.set()                                 # what SIGTERM does
        loop.join(10)
        self.assertFalse(loop.is_alive())
        self.assertEqual(Job.objects.filter(state=Job.State.RUNNING).count(), 0)
        self.assertEqual(Job.objects.filter(state=Job.State.QUEUED, attempts=0).count(), 3)
        # The threads end after the shutdown: they must not count the attempt twice.
        release.set()
        for thread in list(worker.threads):
            thread.join(10)
        self.assertEqual(Job.objects.filter(state=Job.State.QUEUED, attempts=0).count(), 3)


class SigtermTest(TestCase):

    def test_worker_command_stops_on_sigterm(self):
        manage = str(REPO / "src" / "aridi_central" / "manage.py")
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ, ARIDI_DB_PATH=str(Path(tmp) / "aridi.db"))
            subprocess.run([sys.executable, manage, "migrate", "-v0"], env=env, check=True,
                           timeout=120)
            proc = subprocess.Popen([sys.executable, manage, "aridi_worker", "--poll", "0.2"],
                                    env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True)
            time.sleep(3)
            proc.send_signal(signal.SIGTERM)
            output, _ = proc.communicate(timeout=30)
        self.assertEqual(proc.returncode, 0, output)
        self.assertIn("stopping", output)
