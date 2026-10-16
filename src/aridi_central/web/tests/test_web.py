"""Web interface by view and role (TODO.md 5.6) and fleet search (5.7)."""

from datetime import timedelta
from pathlib import Path

from django.contrib.auth.models import Group as Role
from django.contrib.auth.models import User
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from aridi_central.collection.models import Job, Schedule
from aridi_central.inventory.importing import import_bundle
from aridi_central.inventory.models import Group, Machine, Snapshot
from aridi_central.testing import corpus_bundle
from aridi_central.web.roles import ADMIN, READ_ONLY
from aridi_central.web.views import gaps_since

PASSWORD = "a-long-test-password-1"


def user_with(role, name):
    user = User.objects.create_user(name, password=PASSWORD)
    user.groups.add(Role.objects.get(name=role))
    return user


@override_settings(SECURE_SSL_REDIRECT=False)
class WebTest(TestCase):

    @classmethod
    def setUpTestData(cls):
        cls.admin = user_with(ADMIN, "admin")
        cls.reader = user_with(READ_ONLY, "reader")
        cls.machine = Machine.objects.create(name="srv", ssh_target="aridi@srv")
        cls.snapshot = import_bundle(corpus_bundle("debian12", "server"),
                                     machine=cls.machine).snapshot
        cls.group = Group.objects.create(name="web")

    def client_for(self, user):
        client = Client()
        client.force_login(user)
        return client

    # Roles

    def test_anonymous_is_sent_to_login(self):
        for name, args in (("machine-list", []), ("machine-detail", [self.machine.pk]),
                           ("search", []), ("import", []), ("machine-create", [])):
            with self.subTest(view=name):
                response = Client().get(reverse(name, args=args))
                self.assertEqual(response.status_code, 302)
                self.assertTrue(response["Location"].startswith(reverse("login")))

    def test_read_only_can_read(self):
        client = self.client_for(self.reader)
        for name, args in (("machine-list", []), ("machine-detail", [self.machine.pk]),
                           ("machine-history", [self.machine.pk]),
                           ("machine-gaps", [self.machine.pk]),
                           ("snapshot-detail", [self.snapshot.pk]), ("group-list", []),
                           ("job-list", []), ("search", [])):
            with self.subTest(view=name):
                self.assertEqual(client.get(reverse(name, args=args)).status_code, 200)

    def test_read_only_cannot_change_anything(self):
        client = self.client_for(self.reader)
        forbidden = [
            ("get", "machine-create", []), ("post", "machine-create", []),
            ("post", "machine-edit", [self.machine.pk]), ("get", "group-create", []),
            ("post", "group-edit", [self.group.pk]), ("post", "schedule-create", []),
            ("post", "collect", []), ("get", "import", []), ("post", "import", []),
        ]
        for method, name, args in forbidden:
            with self.subTest(view=name, method=method):
                response = getattr(client, method)(reverse(name, args=args),
                                                   {"machine": self.machine.pk})
                self.assertEqual(response.status_code, 403)
        self.assertEqual(Job.objects.count(), 0)
        self.assertEqual(Machine.objects.count(), 1)

    def test_admin_manages_machines_groups_schedules_and_collects(self):
        client = self.client_for(self.admin)
        response = client.post(reverse("machine-create"), {
            "name": "new", "ssh_target": "aridi@new.example", "ssh_port": 22,
            "privilege": "sudo", "groups": [self.group.pk], "active": "on"})
        self.assertEqual(response.status_code, 302)
        new = Machine.objects.get(name="new")
        self.assertEqual(list(new.groups.all()), [self.group])
        response = client.post(reverse("schedule-create"), {
            "group": self.group.pk, "kind": "interval", "every_hours": 12, "active": "on"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(Schedule.objects.get().every_hours, 12)
        client.post(reverse("collect"), {"group": self.group.pk})
        client.post(reverse("collect"), {"machine": [self.machine.pk]})
        self.assertEqual({job.machine.name for job in Job.objects.all()}, {"new", "srv"})

    def test_invalid_ssh_target_is_refused_by_the_form(self):
        response = self.client_for(self.admin).post(reverse("machine-create"), {
            "name": "evil", "ssh_target": "-oProxyCommand=id", "ssh_port": 22,
            "privilege": "sudo"})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(Machine.objects.filter(name="evil").exists())

    def test_csrf_is_required(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.admin)
        response = client.post(reverse("collect"), {"machine": [self.machine.pk]})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(Job.objects.count(), 0)

    def test_open_redirect_is_ignored(self):
        response = self.client_for(self.admin).post(
            reverse("collect"), {"machine": [self.machine.pk], "next": "https://evil.example/"})
        self.assertEqual(response["Location"], reverse("job-list"))

    # Content

    def test_banner_with_script_is_escaped(self):
        response = self.client_for(self.reader).get(
            reverse("machine-detail", args=[self.machine.pk]) + "?detail=1")
        body = response.content.decode()
        self.assertIn("Corpus banner", body)
        self.assertNotIn("<script>alert(1)</script>", body)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", body)
        self.assertNotIn("\x1b", body)
        self.assertIn("default-src 'none'", response["Content-Security-Policy"])

    def test_detail_shows_areas_gaps_and_infrastructure(self):
        response = self.client_for(self.reader).get(
            reverse("machine-detail", args=[self.machine.pk]) + "?detail=1")
        body = response.content.decode()
        for text in ("Packages", "Users and groups", "Infrastructure", "corpus-debian12"):
            self.assertIn(text, body)

    def test_gaps_since(self):
        later = import_bundle(corpus_bundle("debian12", "minimal"), machine=self.machine)
        Snapshot.objects.filter(pk=later.snapshot.pk).update(
            collected_at=self.snapshot.collected_at + timedelta(days=1))
        rows = gaps_since(self.machine)
        latest_gaps = {(g.area, g.item) for g in later.snapshot.gaps.all()}
        self.assertEqual({(r["gap"].area, r["gap"].item) for r in rows}, latest_gaps)
        old = {(g.area, g.item, g.status) for g in self.snapshot.gaps.all()}
        for row in rows:
            key = (row["gap"].area, row["gap"].item, row["gap"].status)
            expected = self.snapshot if key in old else later.snapshot
            self.assertEqual(row["since"], expected)

    def test_import_upload(self):
        client = self.client_for(self.admin)
        upload = SimpleUploadedFile("a.aridi", corpus_bundle("alpine320", "minimal"))
        response = client.post(reverse("import"), {"bundle": upload, "create": "on"})
        self.assertEqual(response.status_code, 302)
        self.assertTrue(Machine.objects.filter(name="corpus-alpine320").exists())
        upload = SimpleUploadedFile("b.aridi", b"garbage")
        response = client.post(reverse("import"), {"bundle": upload, "create": "on"})
        self.assertContains(response, "invalid bundle")

    def test_no_template_or_view_turns_escaping_off(self):
        """CLAUDE.md rule 19: data of machines is never marked safe."""
        root = Path(__file__).resolve().parent.parent.parent
        for path in sorted(root.rglob("*")):
            if path.suffix not in (".html", ".py") or "tests" in path.parts:
                continue
            text = path.read_text(encoding="utf-8")
            for needle in ("|safe", "mark_safe", "autoescape off", "format_html("):
                self.assertNotIn(needle, text, f"{path.name}: {needle}")

    def test_healthz_needs_no_login(self):
        self.assertEqual(Client().get("/healthz").status_code, 200)


@override_settings(SECURE_SSL_REDIRECT=False)
class SearchTest(TestCase):
    """Questions of TODO.md 5.7 over imported corpus snapshots."""

    @classmethod
    def setUpTestData(cls):
        cls.reader = user_with(READ_ONLY, "reader")
        for name, variant in (("debian12", "server"), ("alpine320", "minimal"),
                              ("vm-debian12-arm64", "vm"), ("vm-rocky9-arm64", "vm")):
            machine = Machine.objects.create(name=f"{name}-{variant}")
            import_bundle(corpus_bundle(name, variant), machine=machine)

    def search(self, kind, query):
        client = Client()
        client.force_login(self.reader)
        response = client.get(reverse("search"), {"kind": kind, "query": query})
        self.assertEqual(response.status_code, 200)
        rows = response.context["rows"]
        return None if rows is None else sorted({r.snapshot.machine.name for r in rows})

    def test_package(self):
        self.assertEqual(self.search("package", "openssh-server"),
                         ["vm-debian12-arm64-vm", "vm-rocky9-arm64-vm"])

    def test_port(self):
        # The scenario listener runs in every variant but "minimal".
        self.assertEqual(self.search("port", "8080"),
                         ["debian12-server", "vm-debian12-arm64-vm", "vm-rocky9-arm64-vm"])
        self.assertIn("vm-debian12-arm64-vm", self.search("port", "tcp/22"))

    def test_user(self):
        self.assertEqual(self.search("user", "alice"),
                         ["alpine320-minimal", "debian12-server", "vm-debian12-arm64-vm",
                          "vm-rocky9-arm64-vm"])

    def test_service_and_ip(self):
        self.assertIn("vm-rocky9-arm64-vm", self.search("service", "chronyd"))
        self.assertIn("debian12-server", self.search("ip", "192.0.2.10"))
        self.assertIsNone(self.search("ip", "not-an-ip"))

    def test_only_the_latest_snapshot_counts(self):
        machine = Machine.objects.get(name="debian12-server")
        Snapshot.objects.filter(machine=machine).update(collected_at="2000-01-01T00:00Z")
        import_bundle(corpus_bundle("debian12", "minimal"), machine=machine)
        # The minimal variant has no listener on 8080.
        self.assertNotIn("debian12-server", self.search("port", "8080"))
