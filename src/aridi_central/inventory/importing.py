"""Storing collections: raw bundle → core snapshot → Snapshot, gaps and indexes.

Used by the import of local collections (TODO.md 5.3) and by the SSH collection (5.4).
A raw bundle is untrusted input: the core reader validates it before anything is stored.
"""

import gzip
import hashlib
import logging
from dataclasses import dataclass
from datetime import UTC, datetime

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from aridi import bundle as core_bundle
from aridi.interpret import interpret

from aridi_central.inventory.indexing import index_snapshot
from aridi_central.inventory.models import Machine, Snapshot

log = logging.getLogger(__name__)


class ImportRefused(Exception):
    """The bundle cannot be stored; the message says why and is safe to show."""


class NeedsConfirmation(ImportRefused):
    """The machine was only matched by hostname: the caller has to name it explicitly."""

    def __init__(self, machine, hostname):
        self.machine = machine
        super().__init__(f"the bundle has no known machine id; its hostname {hostname!r} "
                         f"matches machine {machine.name!r}: confirm that machine")


@dataclass
class Stored:
    snapshot: Snapshot
    created: bool


def _collected_at(value):
    """Datetime of the core's "YYYY-MM-DDTHH:MM:SSZ", or now if the bundle has none."""
    if value:
        try:
            return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
        except ValueError:
            log.warning("collected_at %r is not valid, using the reception time", value)
    return timezone.now()


def parse(data):
    """The core snapshot of raw bundle DATA (bytes), or ImportRefused."""
    if len(data) > settings.ARIDI_MAX_BUNDLE_BYTES:
        raise ImportRefused(
            f"the bundle is larger than {settings.ARIDI_MAX_BUNDLE_BYTES} bytes")
    try:
        return interpret(core_bundle.parse(data))
    except core_bundle.BundleError as exc:
        raise ImportRefused(f"invalid bundle: {exc}") from None


def find_machine(core, machine=None, create=False):
    """The Machine a core snapshot belongs to.

    By machine id first. Otherwise MACHINE (named by the user) or, with CREATE, a new
    machine named after the hostname. A hostname match alone is never trusted: it raises
    NeedsConfirmation.
    """
    machine_id = core.machine.machine_id
    hostname = core.machine.hostname
    owner = Machine.objects.filter(machine_id=machine_id).first() if machine_id else None
    if machine is not None:
        if owner is not None and owner != machine:
            raise ImportRefused(
                f"the bundle belongs to machine {owner.name!r} (same machine id)")
        return machine
    if owner is not None:
        return owner
    if hostname:
        by_name = Machine.objects.filter(name=hostname).first()
        if by_name is not None:
            raise NeedsConfirmation(by_name, hostname)
    if create:
        if not hostname:
            raise ImportRefused("the bundle has no hostname: name the machine")
        return Machine.objects.create(name=hostname[:100])
    raise ImportRefused("no machine has this machine id: name the machine or create it")


def store(machine, data, core, origin, installed_sha256=""):
    """Save raw bundle DATA (already parsed into CORE) as a snapshot of MACHINE."""
    digest = hashlib.sha256(data).hexdigest()
    existing = Snapshot.objects.filter(machine=machine, bundle_sha256=digest).first()
    if existing is not None:
        return Stored(existing, False)
    expected = collector_sha256()
    with transaction.atomic():
        snapshot = Snapshot.objects.create(
            machine=machine,
            collected_at=_collected_at(core.collected_at),
            origin=origin,
            schema_version=core.schema_version,
            collector_version=core.collector_version[:64],
            data=core.to_dict(),
            result=core.outcome().value,
            raw_bundle=gzip.compress(data, mtime=0),
            bundle_sha256=digest,
            installed_collector_sha256=installed_sha256,
            collector_outdated=bool(installed_sha256 and expected
                                    and installed_sha256 != expected),
        )
        index_snapshot(snapshot)
        if core.machine.machine_id and not machine.machine_id:
            machine.machine_id = core.machine.machine_id
            machine.save(update_fields=["machine_id"])
    prune_raw_bundles(machine)
    return Stored(snapshot, True)


def store_failure(machine, origin, reason):
    """A collection that produced no snapshot (TODO.md 5.4)."""
    return Snapshot.objects.create(machine=machine, collected_at=timezone.now(), origin=origin,
                                   result=Snapshot.Result.FAILED, failure_reason=reason)


def import_bundle(data, machine=None, create=False):
    """Validate, interpret and store an uploaded raw bundle (TODO.md 5.3)."""
    core = parse(data)
    # The same file again: answer with what was stored, before any machine matching.
    digest = hashlib.sha256(data).hexdigest()
    existing = Snapshot.objects.filter(bundle_sha256=digest).first()
    if existing is not None and machine in (None, existing.machine):
        return Stored(existing, False)
    owner = find_machine(core, machine=machine, create=create)
    return store(owner, data, core, Snapshot.Origin.IMPORT)


def prune_raw_bundles(machine):
    """Keep the raw bundle only in the ARIDI_RAW_RETENTION most recent snapshots."""
    keep = max(settings.ARIDI_RAW_RETENTION, 0)
    old = (Snapshot.objects.filter(machine=machine).exclude(raw_bundle=None)
           .order_by("-collected_at", "-id").values_list("id", flat=True)[keep:])
    Snapshot.objects.filter(id__in=list(old)).update(raw_bundle=None)


_collector_digest = {}


def collector_sha256():
    """SHA-256 of the central's copy of the collector script ("" if it cannot be read)."""
    path = settings.ARIDI_COLLECTOR_SCRIPT
    if path not in _collector_digest:
        try:
            with open(path, "rb") as handle:
                _collector_digest[path] = hashlib.sha256(handle.read()).hexdigest()
        except OSError as exc:
            log.error("cannot read the collector script %s: %s", path, exc)
            return ""
    return _collector_digest[path]
