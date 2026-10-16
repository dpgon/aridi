"""Web of phase 6: alerts, comparison, rules, channels and the relation map (TODO.md 6.1,
6.3, 6.4 and 6.5)."""

import importlib
import ipaddress

from django.contrib.auth.models import Group as Role
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from aridi_central.changes.models import Alert, Channel, RuleOverride
from aridi_central.changes.tests.helpers import add_listening, add_user, snapshot
from aridi_central.changes.tests.test_alerts import stored
from aridi_central.inventory.models import Machine, Snapshot
from aridi_central.web import roles
from aridi_central.web.relation_map import MAX_DRAWN, build
from aridi_central.web.tests.test_web import user_with


def mark_up(snap):
    """The scenario's <script> in a new user's name, to check the escape."""
    return add_user(snap, name="<script>alert(1)</script>")


@override_settings(SECURE_SSL_REDIRECT=False)
class AlertWebTest(TestCase):

    @classmethod
    def setUpTestData(cls):
        cls.admin = user_with(roles.ADMIN, "admin")
        cls.reader = user_with(roles.READ_ONLY, "reader")
        cls.machine = Machine.objects.create(name="srv", ssh_target="aridi@srv")
        cls.first, _ = stored(cls.machine, snapshot())
        cls.second, alerts = stored(cls.machine, mark_up(add_listening(snapshot())), hours=1)
        cls.alert = [a for a in alerts if a.rule == "new_listening_port"][0]

    def client_for(self, user):
        client = Client()
        client.force_login(user)
        return client

    def test_roles_match_the_migrations(self):
        granted = {}
        for name in ("0001_roles", "0002_alert_roles", "0003_network_roles"):
            module = importlib.import_module(f"aridi_central.web.migrations.{name}")
            for role, codes in module.ROLES.items():
                granted.setdefault(role, set()).update(codes)
        self.assertEqual(granted, {name: set(codes) for name, codes in roles.ROLES.items()})
        for name, codes in roles.ROLES.items():
            group = Role.objects.get(name=name)
            have = {f"{p.content_type.app_label}.{p.codename}"
                    for p in group.permissions.select_related("content_type")}
            self.assertEqual(have, set(codes))

    def test_read_only_reads(self):
        client = self.client_for(self.reader)
        for name, args in (("alert-list", []), ("alert-detail", [self.alert.pk]),
                           ("rule-list", []), ("channel-list", []),
                           ("machine-compare", [self.machine.pk]),
                           ("machine-map", [self.machine.pk])):
            with self.subTest(view=name):
                self.assertEqual(client.get(reverse(name, args=args)).status_code, 200)

    def test_read_only_changes_nothing(self):
        client = self.client_for(self.reader)
        override = RuleOverride.objects.create(rule="kernel_changed", machine=self.machine)
        channel = Channel.objects.create(name="ops", kind="email", target="a@example.org")
        for method, name, args in (
                ("post", "alert-state", [self.alert.pk]), ("get", "override-create", []),
                ("post", "override-create", []), ("post", "override-edit", [override.pk]),
                ("post", "override-delete", [override.pk]), ("get", "channel-create", []),
                ("post", "channel-edit", [channel.pk]),
                ("post", "channel-delete", [channel.pk])):
            with self.subTest(view=name, method=method):
                response = getattr(client, method)(reverse(name, args=args),
                                                   {"state": "resolved"})
                self.assertEqual(response.status_code, 403)
        self.alert.refresh_from_db()
        self.assertEqual(self.alert.state, Alert.State.NEW)
        self.assertTrue(RuleOverride.objects.exists() and Channel.objects.exists())

    def test_list_filters_and_escape(self):
        client = self.client_for(self.reader)
        body = client.get(reverse("alert-list")).content.decode()
        self.assertIn("New listening socket tcp 0.0.0.0 port 4444", body)
        self.assertNotIn("<script>alert(1)</script>", body)
        self.assertIn("&lt;script&gt;", body)
        body = client.get(reverse("alert-list"), {"severity": "high"}).content.decode()
        self.assertNotIn("port 4444", body)
        Alert.objects.update(state=Alert.State.RESOLVED)
        self.assertNotIn("port 4444", client.get(reverse("alert-list")).content.decode())
        self.assertIn("port 4444", client.get(reverse("alert-list"),
                                              {"state": "resolved"}).content.decode())

    def test_detail_shows_the_comparison(self):
        body = self.client_for(self.reader).get(
            reverse("alert-detail", args=[self.alert.pk])).content.decode()
        self.assertIn("What changed", body)
        self.assertIn("tcp 0.0.0.0 4444", body)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", body)
        self.assertNotIn("<script>alert(1)</script>", body)

    def test_admin_marks_seen_and_resolved(self):
        client = self.client_for(self.admin)
        for state in ("seen", "resolved"):
            client.post(reverse("alert-state", args=[self.alert.pk]),
                        {"state": state, "note": "known change"})
            self.alert.refresh_from_db()
            self.assertEqual((self.alert.state, self.alert.changed_by, self.alert.note),
                             (state, self.admin, "known change"))

    def test_admin_overrides_and_channels(self):
        client = self.client_for(self.admin)
        response = client.post(reverse("override-create"), {
            "rule": "privileged_user", "machine": self.machine.pk, "silenced": "on"})
        self.assertEqual(response.status_code, 302)
        response = client.post(reverse("override-create"), {
            "rule": "kernel_changed", "machine": self.machine.pk, "threshold": "5"})
        self.assertEqual(response.status_code, 200)        # that rule has no threshold
        with self.settings(ARIDI_WEBHOOKS={"chat": "https://chat.example/secret-token"}):
            response = client.post(reverse("channel-create"), {
                "name": "chat", "kind": "webhook", "target": "chat",
                "min_severity": "low", "active": "on"})
            self.assertEqual(response.status_code, 302)
            body = client.get(reverse("channel-list")).content.decode()
        self.assertIn("chat", body)
        self.assertNotIn("secret-token", body)

    def test_compare_view(self):
        client = self.client_for(self.reader)
        url = reverse("machine-compare", args=[self.machine.pk])
        body = client.get(url).content.decode()            # the last two by default
        self.assertIn("listening sockets", body)
        self.assertIn("tcp 0.0.0.0 4444", body)
        body = client.get(url, {"a": self.second.pk, "b": self.second.pk}).content.decode()
        self.assertNotIn("tcp 0.0.0.0 4444", body)          # a snapshot with itself
        body = client.get(url, {"b": self.second.pk, "volatile": "1"}).content.decode()
        self.assertIn("tcp 0.0.0.0 4444", body)
        other = Machine.objects.create(name="other")
        foreign, _ = stored(other, snapshot())
        self.assertEqual(client.get(url, {"a": foreign.pk}).status_code, 404)
        self.assertEqual(client.get(url, {"a": "x"}).status_code, 404)

    def test_unresponsive_alert_page(self):
        for _ in range(3):
            Snapshot.objects.create(machine=self.machine, collected_at=timezone.now(),
                                    origin="ssh", result="failed", failure_reason="refused")
        from aridi_central.changes.evaluate import evaluate_failure
        alert = evaluate_failure(self.machine.snapshots.filter(result="failed").first())
        body = self.client_for(self.reader).get(
            reverse("alert-detail", args=[alert.pk])).content.decode()
        self.assertIn("does not respond", body)


def with_relations(count, version=4):
    """A snapshot with COUNT remote addresses named in files, v4 or v6."""
    snap = snapshot()
    base = ipaddress.ip_address("198.51.100.0" if version == 4 else "2001:db8::")
    snap["relations"] += [{"ip": str(base + n + 1), "role": "named_in_file",
                           "source": "carving", "detail": "/etc/x"} for n in range(count)]
    return snap


@override_settings(SECURE_SSL_REDIRECT=False)
class RelationMapTest(TestCase):

    def test_build_v4_and_v6(self):
        snap = with_relations(3)
        snap["relations"].append({"ip": "2001:db8::5", "role": "dns_server",
                                  "source": "network", "detail": ""})
        relation_map = build(snap, "host")
        everything = ([str(n.ip) for n in relation_map.outside]
                      + [str(n.ip) for s in relation_map.subnets for n in s.nodes])
        self.assertIn("2001:db8::5", everything)
        self.assertIn("198.51.100.1", everything)
        self.assertTrue(relation_map.local)
        gateways = {str(g) for s in relation_map.subnets for g in s.gateways}
        self.assertIn("192.168.5.2", gateways)
        texts = " ".join(t["text"] for t in relation_map.shapes["texts"])
        self.assertIn("gateway 192.168.5.2", texts)
        self.assertIn("2001:db8::5  dns_server", texts)

    def test_more_than_200_addresses(self):
        relation_map = build(with_relations(450, version=6), "host")
        self.assertGreater(relation_map.total, 450)
        self.assertEqual(relation_map.drawn, MAX_DRAWN)
        drawn = [t for t in relation_map.shapes["texts"] if "named_in_file" in t["text"]]
        self.assertLessEqual(len(drawn), MAX_DRAWN)
        self.assertTrue(any("more in the table" in t["text"]
                            for t in relation_map.shapes["texts"]))

    def test_view_pages_the_table(self):
        machine = Machine.objects.create(name="srv")
        stored(machine, with_relations(250))
        client = Client()
        client.force_login(user_with(roles.READ_ONLY, "reader"))
        url = reverse("machine-map", args=[machine.pk])
        first = client.get(url).content.decode()
        self.assertIn("<svg", first)
        self.assertIn("page 1 of", first)
        self.assertIn("198.51.100.1<", first.replace(" <span", "<"))
        last = client.get(url, {"page": "99"}).content.decode()
        self.assertIn("198.51.100.250", last)
        self.assertNotIn("<script", first)

    def test_view_without_snapshot(self):
        machine = Machine.objects.create(name="empty")
        client = Client()
        client.force_login(user_with(roles.READ_ONLY, "reader"))
        body = client.get(reverse("machine-map", args=[machine.pk])).content.decode()
        self.assertIn("No snapshot yet", body)
