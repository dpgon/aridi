"""From snapshots to alerts (TODO.md 6.3).

Runs when a snapshot is stored (worker and import, through the signals of
inventory/signals.py), when a collection fails, and periodically in the worker for the
machines that stopped sending snapshots.

Only the newest snapshot of a machine is evaluated, against the previous one with data:
importing an old bundle later raises nothing, because its changes are history.
"""

import logging
from datetime import timedelta

from django.db import transaction
from django.utils import timezone

from aridi_central.changes.models import Alert, Channel, Delivery, RuleOverride
from aridi_central.changes.rules import BY_CODE, RANK, RULES, UNRESPONSIVE, Finding
from aridi_central.collection.models import Schedule
from aridi_central.inventory.models import Machine, Snapshot

log = logging.getLogger(__name__)


def effective(rule, machine):
    """(silenced, severity, threshold) of RULE for MACHINE after its overrides."""
    own = RuleOverride.objects.filter(rule=rule.code, machine=machine).first()
    if own is not None:
        return (own.silenced, own.severity or rule.severity,
                rule.threshold if own.threshold is None else own.threshold)
    groups = list(RuleOverride.objects.filter(rule=rule.code,
                                              group__in=machine.groups.all()))
    if not groups:
        return False, rule.severity, rule.threshold
    silenced = all(o.silenced for o in groups)
    severities = [o.severity for o in groups if o.severity]
    thresholds = [o.threshold for o in groups if o.threshold is not None]
    return (silenced, max(severities, key=RANK.get) if severities else rule.severity,
            min(thresholds) if thresholds else rule.threshold)


def raise_alert(machine, rule, severity, finding, snapshot=None, previous=None):
    """Create the alert unless the same one (machine, rule, key) is still open."""
    key = finding.key[:500]
    with transaction.atomic():
        if Alert.objects.filter(machine=machine, rule=rule.code, key=key).exclude(
                state=Alert.State.RESOLVED).exists():
            return None
        alert = Alert.objects.create(machine=machine, rule=rule.code, severity=severity,
                                     key=key, title=finding.title[:500],
                                     detail=finding.detail, snapshot=snapshot,
                                     previous=previous)
        queue_deliveries(alert)
    log.info("alert %s on %s: %s (%s)", alert.id, machine.name, alert.title, severity)
    return alert


def queue_deliveries(alert):
    """A pending delivery for each active channel that wants this alert."""
    groups = set(alert.machine.groups.values_list("id", flat=True))
    for channel in Channel.objects.filter(active=True).prefetch_related("groups"):
        if RANK[alert.severity] < RANK[channel.min_severity]:
            continue
        wanted = {g.id for g in channel.groups.all()}
        if wanted and not wanted & groups:
            continue
        Delivery.objects.create(alert=alert, channel=channel, next_try_at=timezone.now())


def previous_snapshot(snapshot):
    """The snapshot with data just before SNAPSHOT, or None."""
    return (Snapshot.objects.filter(machine=snapshot.machine)
            .exclude(result=Snapshot.Result.FAILED).exclude(id=snapshot.id)
            .filter(collected_at__lte=snapshot.collected_at)
            .order_by("-collected_at", "-id").first())


def is_newest(snapshot):
    return not (Snapshot.objects.filter(machine=snapshot.machine,
                                        collected_at__gt=snapshot.collected_at)
                .exclude(result=Snapshot.Result.FAILED).exists())


def evaluate_snapshot(snapshot):
    """Alerts raised by a newly stored snapshot with data. Returns the new alerts."""
    machine = snapshot.machine
    resolve_unresponsive(machine, snapshot)
    if not is_newest(snapshot):
        log.info("snapshot %s of %s is older than the newest: no alerts", snapshot.id,
                 machine.name)
        return []
    previous = previous_snapshot(snapshot)
    before = previous.data if previous is not None else None
    alerts = []
    for rule in RULES:
        if rule.check is None:
            continue
        silenced, severity, threshold = effective(rule, machine)
        if silenced:
            continue
        for finding in rule.check(before, snapshot.data, threshold):
            alert = raise_alert(machine, rule, severity, finding, snapshot, previous)
            if alert is not None:
                alerts.append(alert)
    return alerts


# Machines that do not respond

def resolve_unresponsive(machine, snapshot):
    """A snapshot with data arrived: the machine answers again."""
    when = snapshot.received_at or timezone.now()
    Alert.objects.filter(machine=machine, rule=UNRESPONSIVE).exclude(
        state=Alert.State.RESOLVED).update(
        state=Alert.State.RESOLVED, updated_at=timezone.now(),
        note=f"Resolved automatically: snapshot received at {when:%Y-%m-%d %H:%M} UTC.")


def _unresponsive(machine, title, detail, snapshot=None):
    rule = BY_CODE[UNRESPONSIVE]
    silenced, severity, _ = effective(rule, machine)
    if silenced:
        return None
    return raise_alert(machine, rule, severity, Finding("unresponsive", title, detail),
                       snapshot=snapshot)


def evaluate_failure(failed):
    """A failed collection (Snapshot with result failed): N in a row raise the alert."""
    machine = failed.machine
    _, _, threshold = effective(BY_CODE[UNRESPONSIVE], machine)
    last_ok = (machine.snapshots.exclude(result=Snapshot.Result.FAILED)
               .order_by("-received_at", "-id").first())
    failures = machine.snapshots.filter(result=Snapshot.Result.FAILED)
    if last_ok is not None:
        failures = failures.filter(received_at__gt=last_ok.received_at)
    count = failures.count()
    if count < threshold:
        return None
    return _unresponsive(machine, f"{machine.name} does not respond: {count} failed "
                                  f"collections in a row",
                         {"failed_in_a_row": count, "last_reason": failed.failure_reason},
                         snapshot=failed)


def period(machine):
    """Shortest period of the active schedules that collect MACHINE, or None."""
    own = list(Schedule.objects.filter(active=True, machine=machine))
    schedules = own or list(Schedule.objects.filter(active=True,
                                                    group__in=machine.groups.all()))
    periods = [timedelta(hours=s.every_hours) if s.kind == Schedule.Kind.INTERVAL
               else timedelta(days=1) for s in schedules
               if s.kind != Schedule.Kind.INTERVAL or s.every_hours]
    return min(periods) if periods else None


def check_silent_machines(now=None):
    """Alert for the scheduled machines without a snapshot for two periods."""
    now = now or timezone.now()
    raised = []
    for machine in Machine.objects.filter(active=True).exclude(ssh_target=""):
        step = period(machine)
        if step is None:
            continue
        last = (machine.snapshots.exclude(result=Snapshot.Result.FAILED)
                .order_by("-received_at").values_list("received_at", flat=True).first())
        since = last or machine.created_at
        if now - since < 2 * step:
            continue
        hours = int(step.total_seconds() // 3600)
        what = (f"last snapshot received {since:%Y-%m-%d %H:%M} UTC" if last
                else "no snapshot since it was added")
        alert = _unresponsive(machine, f"{machine.name} sent no snapshot for two periods "
                                       f"of {hours} h ({what})",
                              {"period_hours": hours,
                               "last_snapshot": since.isoformat() if last else None})
        if alert is not None:
            raised.append(alert)
    return raised


# Signal receivers (connected in apps.py). A failure here must not lose the snapshot,
# which is already stored: it is logged with its traceback.

def on_snapshot_stored(sender, snapshot, **kwargs):
    try:
        evaluate_snapshot(snapshot)
    except Exception:
        log.exception("alert evaluation failed for snapshot %s", snapshot.id)


def on_collection_failed(sender, snapshot, **kwargs):
    try:
        evaluate_failure(snapshot)
    except Exception:
        log.exception("alert evaluation failed for failed collection %s", snapshot.id)
