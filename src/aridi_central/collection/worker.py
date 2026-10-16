"""The worker: takes queued jobs, runs them with bounded concurrency, creates the scheduled
ones (TODO.md 5.5), evaluates silent machines and sends alerts (phase 6), and runs the
scans of authorized networks (phase 7). Standard library threads and Django only.
"""

import logging
import os
import socket
import threading
import time
from datetime import timedelta

from django.conf import settings
from django.db import close_old_connections, connection, transaction
from django.db.models import F, Q
from django.utils import timezone

from aridi_central.changes.channels import process_deliveries
from aridi_central.changes.evaluate import check_silent_machines
from aridi_central.collection import ssh
from aridi_central.collection.models import Job, Schedule
from aridi_central.discovery.scanning import run_scan
from aridi_central.inventory.importing import ImportRefused, parse, store, store_failure
from aridi_central.inventory.models import Machine, Snapshot

log = logging.getLogger(__name__)

PENDING = (Job.State.QUEUED, Job.State.RUNNING)


def enqueue(machines, origin=Snapshot.Origin.ON_DEMAND, user=None):
    """Queue one collection per active machine that has no pending one. Returns the jobs."""
    jobs = []
    for machine in machines:
        if not machine.active or not machine.ssh_target:
            continue
        with transaction.atomic():
            if Job.objects.filter(machine=machine, kind=Job.Kind.COLLECT,
                                  state__in=PENDING).exists():
                continue
            jobs.append(Job.objects.create(machine=machine, origin=origin, requested_by=user,
                                           max_attempts=settings.ARIDI_JOB_ATTEMPTS))
    return jobs


def enqueue_scan(network, origin=Snapshot.Origin.ON_DEMAND, user=None):
    """Queue a scan of NETWORK unless one is pending. Returns the job or None."""
    if not network.active:
        return None
    with transaction.atomic():
        if Job.objects.filter(network=network, kind=Job.Kind.SCAN,
                              state__in=PENDING).exists():
            return None
        # A scan is not retried: a failure says why (disabled, inactive network…).
        return Job.objects.create(kind=Job.Kind.SCAN, network=network, origin=origin,
                                  requested_by=user, max_attempts=1)


def backoff(attempts):
    """Wait before retry number ATTEMPTS: 1, 2, 4… minutes, at most one hour."""
    return timedelta(minutes=min(2 ** max(attempts - 1, 0), 60))


class Worker:
    def __init__(self, max_ssh=None, poll_seconds=5, name=None, collect=ssh.collect,
                 shutdown_grace=30, silence_check_seconds=60):
        self.max_ssh = max_ssh or settings.ARIDI_MAX_SSH
        self.poll_seconds = poll_seconds
        self.name = name or f"{socket.gethostname()}:{os.getpid()}"
        self.collect = collect
        self.shutdown_grace = shutdown_grace
        self.stop = threading.Event()
        self.slots = threading.BoundedSemaphore(self.max_ssh)
        self.threads = set()
        self.lock = threading.Lock()
        self.running = 0
        self.max_running = 0     # highest concurrency seen (tests)
        self.silence_check_seconds = silence_check_seconds
        self.last_silence_check = None

    # Queue

    def claim(self, limit):
        """Take up to LIMIT queued jobs. The conditional UPDATE makes each take atomic."""
        now = timezone.now()
        taken, tried = [], set()
        while len(taken) < limit:
            # Another worker may take the same candidates first: then look further.
            candidates = list(
                Job.objects.filter(state=Job.State.QUEUED)
                .filter(Q(not_before__isnull=True) | Q(not_before__lte=now))
                .exclude(id__in=tried).order_by("created_at", "id")
                .values_list("id", flat=True)[:limit - len(taken)])
            if not candidates:
                break
            for job_id in candidates:
                tried.add(job_id)
                updated = Job.objects.filter(id=job_id, state=Job.State.QUEUED).update(
                    state=Job.State.RUNNING, started_at=now, worker=self.name,
                    attempts=F("attempts") + 1)
                if updated:
                    taken.append(Job.objects.get(id=job_id))
        return taken

    def run_scan_job(self, job):
        outcome = run_scan(job, stop=self.stop)
        if not outcome.ok and self.stop.is_set():
            Job.objects.filter(id=job.id, state=Job.State.RUNNING).update(
                state=Job.State.QUEUED, attempts=F("attempts") - 1, worker="",
                reason="interrupted by the worker shutdown")
            return
        state = Job.State.DONE if outcome.ok else Job.State.FAILED
        reason = outcome.reason or f"{outcome.found} open port(s)"
        Job.objects.filter(id=job.id).update(state=state, finished_at=timezone.now(),
                                             reason=reason)
        (log.info if outcome.ok else log.error)("job %s: scan of %s: %s", job.id,
                                                 job.network, reason)

    def run_job(self, job):
        """Collect, store, and mark JOB done, retriable or failed."""
        if job.kind == Job.Kind.SCAN:
            return self.run_scan_job(job)
        machine = job.machine
        result = self.collect(machine)
        if self.stop.is_set() and not result.ok:
            # Killed by the shutdown: it was not the machine's fault. shutdown() may have
            # put it back in the queue already.
            Job.objects.filter(id=job.id, state=Job.State.RUNNING).update(
                state=Job.State.QUEUED, attempts=F("attempts") - 1, worker="",
                reason="interrupted by the worker shutdown")
            return
        snapshot = None
        reason = result.reason
        if result.ok:
            try:
                core = parse(result.bundle)
                snapshot = store(machine, result.bundle, core, job.origin,
                                 installed_sha256=result.installed_sha256).snapshot
            except ImportRefused as exc:
                reason = str(exc)
        now = timezone.now()
        if snapshot is not None:
            Job.objects.filter(id=job.id).update(state=Job.State.DONE, finished_at=now,
                                                 snapshot=snapshot, reason="")
            log.info("job %s: %s collected (%s)", job.id, machine.name, snapshot.result)
            return
        job.refresh_from_db()
        if job.attempts < job.max_attempts:
            Job.objects.filter(id=job.id).update(state=Job.State.QUEUED, worker="",
                                                 not_before=now + backoff(job.attempts),
                                                 reason=reason)
            log.warning("job %s: %s failed, will retry: %s", job.id, machine.name, reason)
            return
        failed = store_failure(machine, job.origin, reason)
        Job.objects.filter(id=job.id).update(state=Job.State.FAILED, finished_at=now,
                                             snapshot=failed, reason=reason)
        log.error("job %s: %s failed: %s", job.id, machine.name, reason)

    def _thread(self, job):
        with self.lock:
            self.running += 1
            self.max_running = max(self.max_running, self.running)
        try:
            self.run_job(job)
        except Exception:
            log.exception("job %s crashed", job.id)
            Job.objects.filter(id=job.id).update(
                state=Job.State.FAILED, finished_at=timezone.now(),
                reason="internal error of the worker (see its log)")
        finally:
            with self.lock:
                self.running -= 1
            self.slots.release()
            connection.close()
            self.threads.discard(threading.current_thread())

    def dispatch(self):
        """Start a thread per claimed job, never more than max_ssh at once."""
        free = 0
        while self.slots.acquire(blocking=False):
            free += 1
        if not free:
            return 0
        jobs = self.claim(free)
        for _ in range(free - len(jobs)):
            self.slots.release()
        for job in jobs:
            thread = threading.Thread(target=self._thread, args=(job,), name=f"job-{job.id}",
                                      daemon=True)
            self.threads.add(thread)
            thread.start()
        return len(jobs)

    # Schedules

    def due_schedules(self):
        """Queue the jobs of the schedules whose time came. One run per period."""
        now = timezone.now()
        created = []
        for schedule in Schedule.objects.filter(active=True).filter(
                Q(next_run_at__isnull=True) | Q(next_run_at__lte=now)):
            if schedule.next_run_at is None:
                # A new schedule waits for its first period.
                Schedule.objects.filter(id=schedule.id, next_run_at__isnull=True).update(
                    next_run_at=schedule.following(now))
                continue
            following = schedule.following(now)
            # Conditional update: only the worker that moves next_run_at enqueues.
            moved = Schedule.objects.filter(id=schedule.id,
                                            next_run_at=schedule.next_run_at).update(
                next_run_at=following)
            if not moved:
                continue
            if schedule.network_id:
                job = enqueue_scan(schedule.network, origin=Snapshot.Origin.SSH)
                created += [job] if job else []
                continue
            created += enqueue(self.targets(schedule), origin=Snapshot.Origin.SSH)
        return created

    @staticmethod
    def targets(schedule):
        if schedule.machine_id:
            return [schedule.machine]
        own = Schedule.objects.filter(active=True, machine__isnull=False).values("machine")
        return list(Machine.objects.filter(groups=schedule.group, active=True)
                    .exclude(id__in=own).distinct())

    # Life cycle

    def recover(self):
        """Jobs left 'running' by a worker that died go back to the queue."""
        limit = timezone.now() - timedelta(seconds=settings.ARIDI_SSH_TIMEOUT * 2)
        return Job.objects.filter(state=Job.State.RUNNING, started_at__lt=limit).update(
            state=Job.State.QUEUED, worker="", reason="recovered after a worker stopped")

    # Alerts (phase 6)

    def silent_machines(self):
        """Every silence_check_seconds: machines without a snapshot for two periods."""
        now = time.monotonic()
        if (self.last_silence_check is not None
                and now - self.last_silence_check < self.silence_check_seconds):
            return []
        self.last_silence_check = now
        return check_silent_machines()

    def deliveries_forever(self):
        """Own thread: a slow or dead channel never delays the collections."""
        while not self.stop.is_set():
            close_old_connections()
            try:
                process_deliveries()
            except Exception:
                log.exception("alert delivery loop failed; retrying")
            self.stop.wait(self.poll_seconds)
        connection.close()

    def run_forever(self):
        log.info("worker %s started (max %d SSH sessions)", self.name, self.max_ssh)
        self.recover()
        sender = threading.Thread(target=self.deliveries_forever, name="deliveries",
                                  daemon=True)
        sender.start()
        while not self.stop.is_set():
            close_old_connections()
            try:
                self.due_schedules()
                self.dispatch()
                self.silent_machines()
                self.beat()
            except Exception:
                log.exception("worker loop failed; retrying")
            self.stop.wait(self.poll_seconds)
        self.shutdown()
        sender.join(self.shutdown_grace)

    @staticmethod
    def beat():
        """Touch ARIDI_WORKER_HEARTBEAT: the healthcheck reads its age."""
        if settings.ARIDI_WORKER_HEARTBEAT:
            with open(settings.ARIDI_WORKER_HEARTBEAT, "w") as handle:
                handle.write(timezone.now().isoformat())

    def shutdown(self):
        """Stop: running ssh sessions are left shutdown_grace seconds to finish."""
        log.info("worker %s stopping, %d job(s) running", self.name, len(self.threads))
        self.stop.set()
        deadline = time.monotonic() + self.shutdown_grace
        for thread in list(self.threads):
            thread.join(max(deadline - time.monotonic(), 0))
        # What is still running goes back to the queue instead of staying "running".
        Job.objects.filter(state=Job.State.RUNNING, worker=self.name).update(
            state=Job.State.QUEUED, attempts=F("attempts") - 1, worker="",
            reason="interrupted by the worker shutdown")
