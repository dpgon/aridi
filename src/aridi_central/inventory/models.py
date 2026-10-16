"""Inventory model (TODO.md 5.2, docs/CAMBIO.md "Modelo de datos").

A Snapshot keeps the whole JSON produced by the core; the index tables are derived from
it (indexing.py) so that the fleet can be searched. Machines never hold credentials.
"""

from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.db.models import Q

from aridi_central.inventory.validators import validate_proxy_jump, validate_ssh_target


class Group(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name


class Machine(models.Model):
    class Privilege(models.TextChoices):
        # Decision of TODO.md 5.0: the script installed at a fixed path, run with sudo.
        SUDO = "sudo", "root, through sudo and the installed script"
        # No sudo rule: the script goes through stdin and runs as the SSH user.
        USER = "user", "the SSH user, without sudo (gaps where root is needed)"

    name = models.CharField(max_length=100, unique=True)
    ssh_target = models.CharField(
        max_length=255, blank=True, validators=[validate_ssh_target],
        help_text="user@host. Empty for machines that are only imported.")
    ssh_port = models.PositiveIntegerField(
        default=22, validators=[MinValueValidator(1), MaxValueValidator(65535)])
    proxy_jump = models.CharField(max_length=255, blank=True,
                                  validators=[validate_proxy_jump])
    privilege = models.CharField(max_length=8, choices=Privilege.choices,
                                 default=Privilege.SUDO)
    groups = models.ManyToManyField(Group, blank=True, related_name="machines")
    # From the collected snapshots (/etc/machine-id); it links imports to the machine.
    machine_id = models.CharField(max_length=32, blank=True, db_index=True)
    active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name

    def latest_snapshot(self):
        """The most recent snapshot that has data (failed collections have none)."""
        return (self.snapshots.exclude(result=Snapshot.Result.FAILED)
                .order_by("-collected_at", "-id").first())


class Snapshot(models.Model):
    class Origin(models.TextChoices):
        SSH = "ssh", "scheduled SSH collection"
        ON_DEMAND = "on_demand", "on-demand SSH collection"
        IMPORT = "import", "imported bundle"

    class Result(models.TextChoices):
        COMPLETE = "complete", "complete"
        GAPS = "gaps", "with gaps"
        FAILED = "failed", "failed"

    machine = models.ForeignKey(Machine, on_delete=models.CASCADE, related_name="snapshots")
    # Collection time from the bundle; for a failed collection, when it was attempted.
    collected_at = models.DateTimeField(db_index=True)
    received_at = models.DateTimeField(auto_now_add=True)
    origin = models.CharField(max_length=12, choices=Origin.choices)
    schema_version = models.PositiveSmallIntegerField(null=True, blank=True)
    collector_version = models.CharField(max_length=64, blank=True)
    data = models.JSONField(null=True, blank=True)
    result = models.CharField(max_length=8, choices=Result.choices, db_index=True)
    failure_reason = models.TextField(blank=True)
    # gzip of the raw bundle, only for the most recent snapshots (ARIDI_RAW_RETENTION).
    raw_bundle = models.BinaryField(null=True, blank=True)
    bundle_sha256 = models.CharField(max_length=64, blank=True, db_index=True)
    # SHA-256 of the script installed on the machine, reported over SSH (TODO.md 5.0).
    installed_collector_sha256 = models.CharField(max_length=64, blank=True)
    collector_outdated = models.BooleanField(default=False)

    class Meta:
        ordering = ["-collected_at", "-id"]
        constraints = [
            models.UniqueConstraint(fields=["machine", "bundle_sha256"],
                                    condition=~Q(bundle_sha256=""),
                                    name="snapshot_unique_bundle_per_machine"),
        ]

    def __str__(self):
        return f"{self.machine} {self.collected_at:%Y-%m-%d %H:%M} {self.result}"


class Gap(models.Model):
    """Something the snapshot could not see: a whole area (item empty) or part of it."""

    snapshot = models.ForeignKey(Snapshot, on_delete=models.CASCADE, related_name="gaps")
    area = models.CharField(max_length=32)
    item = models.CharField(max_length=200, blank=True)
    status = models.CharField(max_length=16)
    reason = models.TextField(blank=True)

    class Meta:
        ordering = ["id"]


# Search indexes: rows derived from the non-volatile areas of each snapshot.

class SnapshotPackage(models.Model):
    snapshot = models.ForeignKey(Snapshot, on_delete=models.CASCADE, related_name="packages")
    name = models.CharField(max_length=255, db_index=True)
    version = models.CharField(max_length=255, blank=True)
    arch = models.CharField(max_length=32, blank=True)
    manager = models.CharField(max_length=16, blank=True)


class SnapshotUser(models.Model):
    snapshot = models.ForeignKey(Snapshot, on_delete=models.CASCADE, related_name="users")
    name = models.CharField(max_length=255, db_index=True)
    uid = models.BigIntegerField(null=True)
    shell = models.CharField(max_length=255, blank=True)
    password_algo = models.CharField(max_length=32, blank=True)
    groups = models.TextField(blank=True, help_text="Comma separated group names")


class SnapshotPort(models.Model):
    snapshot = models.ForeignKey(Snapshot, on_delete=models.CASCADE, related_name="ports")
    proto = models.CharField(max_length=8, db_index=True)
    family = models.PositiveSmallIntegerField()
    address = models.CharField(max_length=64)
    port = models.PositiveIntegerField(db_index=True)
    process = models.CharField(max_length=255, blank=True)


class SnapshotService(models.Model):
    snapshot = models.ForeignKey(Snapshot, on_delete=models.CASCADE, related_name="services")
    manager = models.CharField(max_length=16)
    name = models.CharField(max_length=255, db_index=True)
    state = models.CharField(max_length=32, blank=True)
    enabled = models.CharField(max_length=32, blank=True)


class Relation(models.Model):
    snapshot = models.ForeignKey(Snapshot, on_delete=models.CASCADE, related_name="relations")
    ip = models.GenericIPAddressField(db_index=True)
    role = models.CharField(max_length=32)
    source = models.CharField(max_length=32)
    detail = models.TextField(blank=True)
