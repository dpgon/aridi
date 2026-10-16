"""Job queue and schedules of the worker (TODO.md 5.5).

The queue lives in the database: no Celery or Redis. A job is taken with a conditional
UPDATE (state='queued' → 'running'), so two workers never run the same job.
"""

from datetime import datetime, timedelta

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models import Q

from aridi_central.inventory.models import Group, Machine, Snapshot


class Job(models.Model):
    class Kind(models.TextChoices):
        COLLECT = "collect", "collection"
        SCAN = "scan", "scan"            # phase 7

    class State(models.TextChoices):
        QUEUED = "queued", "queued"
        RUNNING = "running", "running"
        DONE = "done", "done"
        FAILED = "failed", "failed"

    kind = models.CharField(max_length=8, choices=Kind.choices, default=Kind.COLLECT)
    machine = models.ForeignKey(Machine, on_delete=models.CASCADE, related_name="jobs")
    origin = models.CharField(max_length=12, choices=Snapshot.Origin.choices,
                              default=Snapshot.Origin.ON_DEMAND)
    state = models.CharField(max_length=8, choices=State.choices, default=State.QUEUED,
                             db_index=True)
    attempts = models.PositiveSmallIntegerField(default=0)
    max_attempts = models.PositiveSmallIntegerField(default=3)
    created_at = models.DateTimeField(auto_now_add=True)
    # Earliest start: retries wait (backoff).
    not_before = models.DateTimeField(null=True, blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    worker = models.CharField(max_length=100, blank=True)
    reason = models.TextField(blank=True)
    snapshot = models.ForeignKey(Snapshot, null=True, blank=True, on_delete=models.SET_NULL,
                                 related_name="jobs")
    requested_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True,
                                     on_delete=models.SET_NULL, related_name="+")

    class Meta:
        ordering = ["-created_at", "-id"]

    def __str__(self):
        return f"{self.kind} {self.machine} {self.state}"


class Schedule(models.Model):
    """Periodic collection of one machine or of a group (its default schedule).

    A machine with its own active schedule is left out of its groups' schedules.
    """

    class Kind(models.TextChoices):
        INTERVAL = "interval", "every N hours"
        DAILY = "daily", "daily at a UTC time"

    machine = models.ForeignKey(Machine, null=True, blank=True, on_delete=models.CASCADE,
                                related_name="schedules")
    group = models.ForeignKey(Group, null=True, blank=True, on_delete=models.CASCADE,
                              related_name="schedules")
    kind = models.CharField(max_length=8, choices=Kind.choices, default=Kind.DAILY)
    every_hours = models.PositiveIntegerField(null=True, blank=True)
    daily_at = models.TimeField(null=True, blank=True, help_text="UTC")
    active = models.BooleanField(default=True)
    next_run_at = models.DateTimeField(null=True, blank=True, db_index=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=(Q(machine__isnull=False, group__isnull=True)
                           | Q(machine__isnull=True, group__isnull=False)),
                name="schedule_machine_xor_group"),
        ]

    def __str__(self):
        target = self.machine or self.group
        when = (f"every {self.every_hours} h" if self.kind == self.Kind.INTERVAL
                else f"daily at {self.daily_at:%H:%M} UTC" if self.daily_at else "daily")
        return f"{target}: {when}"

    def clean(self):
        if (self.machine is None) == (self.group is None):
            raise ValidationError("A schedule is for one machine or for one group.")
        if self.kind == self.Kind.INTERVAL and not self.every_hours:
            raise ValidationError({"every_hours": "Required for an interval schedule."})
        if self.kind == self.Kind.DAILY and self.daily_at is None:
            raise ValidationError({"daily_at": "Required for a daily schedule."})

    def following(self, after):
        """First run time strictly after AFTER: one per period, missed periods skipped."""
        if self.kind == self.Kind.INTERVAL:
            step = timedelta(hours=self.every_hours)
            start = self.next_run_at or after
            if start > after:
                return start
            missed = (after - start) // step + 1
            return start + missed * step
        today = datetime.combine(after.date(), self.daily_at, tzinfo=after.tzinfo)
        return today if today > after else today + timedelta(days=1)
