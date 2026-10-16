"""Alerts from stored snapshots, overrides and machines that do not respond (TODO.md 6.2
and 6.3)."""

from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from aridi_central.changes.evaluate import (check_silent_machines, effective,
                                            evaluate_snapshot)
from aridi_central.changes.models import Alert, RuleOverride
from aridi_central.changes.rules import BY_CODE, UNRESPONSIVE
from aridi_central.changes.tests.helpers import add_listening, add_user, snapshot
from aridi_central.collection.models import Job, Schedule
from aridi_central.collection.ssh import Result
from aridi_central.collection.worker import Worker, enqueue
from aridi_central.inventory.importing import import_bundle, store_failure
from aridi_central.inventory.models import Group, Machine, Snapshot
from aridi_central.testing import corpus_bundle

T0 = timezone.now() - timedelta(days=10)


def stored(machine, data, hours=0):
    """A snapshot with DATA, collected HOURS after T0, evaluated like a stored one."""
    snap = Snapshot.objects.create(machine=machine, collected_at=T0 + timedelta(hours=hours),
                                   origin=Snapshot.Origin.SSH, data=data,
                                   result=Snapshot.Result.COMPLETE)
    return snap, evaluate_snapshot(snap)


def changed():
    return add_listening(add_user(snapshot()))


class EvaluationTest(TestCase):

    def setUp(self):
        self.machine = Machine.objects.create(name="srv", ssh_target="aridi@srv")

    def test_changes_raise_the_expected_alerts(self):
        first, alerts = stored(self.machine, snapshot())
        self.assertEqual(alerts, [])
        second, alerts = stored(self.machine, changed(), hours=1)
        self.assertEqual(sorted((a.rule, a.key, a.severity) for a in alerts),
                         [("new_listening_port", "tcp/0.0.0.0/4444", "medium"),
                          ("privileged_user", "mallory:new", "high")])
        for alert in alerts:
            self.assertEqual((alert.snapshot, alert.previous), (second, first))
            self.assertEqual(alert.state, Alert.State.NEW)

    def test_no_duplicates_in_later_collections_without_new_change(self):
        stored(self.machine, snapshot())
        stored(self.machine, changed(), hours=1)
        _, again = stored(self.machine, changed(), hours=2)
        self.assertEqual(again, [])
        Alert.objects.update(state=Alert.State.RESOLVED)
        _, after_resolving = stored(self.machine, changed(), hours=3)
        self.assertEqual(after_resolving, [])
        self.assertEqual(Alert.objects.count(), 2)

    def test_open_alert_is_not_raised_twice(self):
        stored(self.machine, snapshot())
        stored(self.machine, changed(), hours=1)
        stored(self.machine, snapshot(), hours=2)          # the user and port go away
        _, back = stored(self.machine, changed(), hours=3)  # and come back
        self.assertEqual(back, [])                          # the alerts are still open
        Alert.objects.update(state=Alert.State.RESOLVED)
        stored(self.machine, snapshot(), hours=4)
        _, once_more = stored(self.machine, changed(), hours=5)
        self.assertEqual(len(once_more), 2)

    def test_older_snapshot_imported_later_raises_nothing(self):
        stored(self.machine, snapshot(), hours=5)
        _, alerts = stored(self.machine, changed(), hours=1)
        self.assertEqual(alerts, [])

    def test_signal_on_import(self):
        stored(self.machine, add_user(snapshot("debian12", "server"), name="old-user"))
        result = import_bundle(corpus_bundle("debian12", "server"), machine=self.machine)
        self.assertTrue(result.created)
        # The import is the newest: compared with the synthetic one, nothing new appears
        # but a user went away, which no rule alerts about.
        self.assertEqual(Alert.objects.count(), 0)
        Snapshot.objects.filter(pk=result.snapshot.pk).update(collected_at=T0)
        stored(self.machine, add_listening(snapshot("debian12", "server")), hours=1)
        self.assertEqual(list(Alert.objects.values_list("rule", flat=True)),
                         ["new_listening_port"])


class OverrideTest(TestCase):

    def setUp(self):
        self.machine = Machine.objects.create(name="srv", ssh_target="aridi@srv")
        self.web = Group.objects.create(name="web")
        self.db = Group.objects.create(name="db")
        self.machine.groups.add(self.web, self.db)
        self.rule = BY_CODE["disk_full"]

    def test_silenced_for_the_machine(self):
        RuleOverride.objects.create(rule="privileged_user", machine=self.machine,
                                    silenced=True)
        stored(self.machine, snapshot())
        _, alerts = stored(self.machine, changed(), hours=1)
        self.assertEqual([a.rule for a in alerts], ["new_listening_port"])

    def test_silenced_for_a_group(self):
        for group in (self.web, self.db):
            RuleOverride.objects.create(rule="new_listening_port", group=group,
                                        silenced=True)
        stored(self.machine, snapshot())
        _, alerts = stored(self.machine, changed(), hours=1)
        self.assertEqual([a.rule for a in alerts], ["privileged_user"])

    def test_defaults(self):
        self.assertEqual(effective(self.rule, self.machine), (False, "medium", 90))

    def test_machine_wins_over_group(self):
        RuleOverride.objects.create(rule="disk_full", group=self.web, silenced=True)
        RuleOverride.objects.create(rule="disk_full", machine=self.machine, threshold=80)
        self.assertEqual(effective(self.rule, self.machine), (False, "medium", 80))

    def test_conflicting_groups_alert_most(self):
        RuleOverride.objects.create(rule="disk_full", group=self.web, silenced=True,
                                    severity="low", threshold=95)
        RuleOverride.objects.create(rule="disk_full", group=self.db, severity="high",
                                    threshold=85)
        self.assertEqual(effective(self.rule, self.machine), (False, "high", 85))

    def test_severity_override(self):
        RuleOverride.objects.create(rule="new_listening_port", machine=self.machine,
                                    severity="high")
        stored(self.machine, snapshot())
        _, alerts = stored(self.machine, add_listening(snapshot()), hours=1)
        self.assertEqual([(a.rule, a.severity) for a in alerts],
                         [("new_listening_port", "high")])


def failing(machine):
    return Result(False, reason="connection refused")


class UnresponsiveTest(TestCase):

    def setUp(self):
        self.machine = Machine.objects.create(name="srv", ssh_target="aridi@srv")

    def fail(self, times):
        for _ in range(times):
            store_failure(self.machine, Snapshot.Origin.SSH, "connection refused")

    def unresponsive(self):
        return list(Alert.objects.filter(rule=UNRESPONSIVE).values_list("state", flat=True))

    def test_three_failures_in_a_row(self):
        stored(self.machine, snapshot())
        self.fail(2)
        self.assertEqual(self.unresponsive(), [])
        self.fail(1)
        self.assertEqual(self.unresponsive(), ["new"])
        self.fail(3)
        self.assertEqual(self.unresponsive(), ["new"])     # not raised again while open
        alert = Alert.objects.get(rule=UNRESPONSIVE)
        self.assertEqual(alert.detail["failed_in_a_row"], 3)
        self.assertEqual(alert.detail["last_reason"], "connection refused")

    def test_a_snapshot_resolves_it(self):
        self.fail(3)
        stored(self.machine, snapshot(), hours=24 * 20)
        self.assertEqual(self.unresponsive(), ["resolved"])
        self.assertIn("Resolved automatically", Alert.objects.get().note)
        self.fail(2)
        self.assertEqual(self.unresponsive(), ["resolved"])   # count starts again

    def test_threshold_and_silence_overrides(self):
        RuleOverride.objects.create(rule=UNRESPONSIVE, machine=self.machine, threshold=1)
        self.fail(1)
        self.assertEqual(self.unresponsive(), ["new"])
        Alert.objects.all().delete()
        RuleOverride.objects.filter(rule=UNRESPONSIVE).update(silenced=True)
        self.fail(5)
        self.assertEqual(self.unresponsive(), [])

    def test_through_the_worker(self):
        worker = Worker(collect=failing)
        for _ in range(3):
            [job] = enqueue([self.machine])
            Job.objects.filter(pk=job.pk).update(max_attempts=1)
            worker.run_job(worker.claim(1)[0])
        self.assertEqual(self.unresponsive(), ["new"])

    def test_no_snapshot_for_two_periods(self):
        Schedule.objects.create(machine=self.machine, kind=Schedule.Kind.INTERVAL,
                                every_hours=6)
        snap, _ = stored(self.machine, snapshot())
        received = timezone.now() - timedelta(hours=11)
        Snapshot.objects.filter(pk=snap.pk).update(received_at=received)
        self.assertEqual(check_silent_machines(), [])
        Snapshot.objects.filter(pk=snap.pk).update(received_at=received - timedelta(hours=2))
        [alert] = check_silent_machines()
        self.assertEqual(alert.detail["period_hours"], 6)
        self.assertEqual(check_silent_machines(), [])          # still open

    def test_group_schedule_and_machines_without_schedule(self):
        other = Machine.objects.create(name="unscheduled", ssh_target="aridi@x")
        group = Group.objects.create(name="g")
        self.machine.groups.add(group)
        Schedule.objects.create(group=group, kind=Schedule.Kind.DAILY,
                                daily_at=timezone.now().time())
        Machine.objects.filter(pk__in=[self.machine.pk, other.pk]).update(
            created_at=timezone.now() - timedelta(days=3))
        alerts = check_silent_machines()
        self.assertEqual([a.machine for a in alerts], [self.machine])
        self.assertIn("no snapshot since it was added", alerts[0].title)
