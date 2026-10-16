"""Inventory model, indexes and import of local collections (TODO.md 5.2 and 5.3)."""

import gzip
import io

from django.core.management import CommandError, call_command
from django.test import TestCase, override_settings

from aridi import bundle as core_bundle
from aridi.interpret import interpret

from aridi_central.inventory.importing import (ImportRefused, NeedsConfirmation,
                                               import_bundle)
from aridi_central.inventory.models import (Gap, Machine, Relation, Snapshot,
                                            SnapshotPackage, SnapshotPort, SnapshotService,
                                            SnapshotUser)
from aridi_central.inventory.validators import SSH_TARGET
from aridi_central.testing import CORPUS, corpus_bundle

SAMPLES = (("debian12", "server"), ("alpine320", "server"), ("vm-rocky9-arm64", "vm"))
VOLATILE = {"processes", "load", "connections", "neighbours"}


class IndexingTest(TestCase):

    def test_counts_equal_to_the_snapshot(self):
        for name, variant in SAMPLES:
            with self.subTest(sample=f"{name}/{variant}"):
                data = corpus_bundle(name, variant)
                core = interpret(core_bundle.parse(data))
                snapshot = import_bundle(data, create=True).snapshot
                sections = core.sections
                self.assertEqual(snapshot.result, core.outcome().value)
                self.assertEqual(SnapshotPackage.objects.filter(snapshot=snapshot).count(),
                                 len(sections["packages"].data["packages"]))
                self.assertEqual(SnapshotUser.objects.filter(snapshot=snapshot).count(),
                                 len(sections["users"].data["users"]))
                self.assertEqual(SnapshotPort.objects.filter(snapshot=snapshot).count(),
                                 len(sections["network"].data["listening"]))
                self.assertEqual(SnapshotService.objects.filter(snapshot=snapshot).count(),
                                 len(sections["services"].data["services"]))
                self.assertEqual(Gap.objects.filter(snapshot=snapshot).count(),
                                 len(core.gaps()))
                stable = [r for r in core.relations if r.source not in VOLATILE]
                self.assertEqual(Relation.objects.filter(snapshot=snapshot).count(),
                                 len(stable))

    def test_volatile_areas_are_not_indexed(self):
        data = corpus_bundle("vm-rocky9-arm64", "vm")
        core = interpret(core_bundle.parse(data))
        volatile = {r.source for r in core.relations} & VOLATILE
        self.assertTrue(volatile, "the VM sample has relations from volatile areas")
        snapshot = import_bundle(data, create=True).snapshot
        sources = set(Relation.objects.filter(snapshot=snapshot)
                      .values_list("source", flat=True))
        self.assertFalse(sources & VOLATILE)
        # The JSON keeps everything, volatile areas included.
        self.assertIn("processes", snapshot.data["sections"])


class ImportTest(TestCase):

    def test_every_corpus_bundle_imports(self):
        paths = sorted(CORPUS.glob("*/*/bundle.aridi"))
        self.assertGreater(len(paths), 30)
        for path in paths:
            with self.subTest(bundle=str(path.relative_to(CORPUS))):
                machine = Machine.objects.create(name=f"{path.parent.parent.name}-"
                                                      f"{path.parent.name}")
                stored = import_bundle(path.read_bytes(), machine=machine)
                self.assertTrue(stored.created)
                self.assertIn(stored.snapshot.result, ("complete", "gaps"))
                self.assertEqual(gzip.decompress(stored.snapshot.raw_bundle),
                                 path.read_bytes())

    def test_same_collection_twice_is_not_duplicated(self):
        data = corpus_bundle("debian12", "minimal")
        first = import_bundle(data, create=True)
        second = import_bundle(data)          # same file: found by its SHA-256
        self.assertFalse(second.created)
        self.assertEqual(first.snapshot.pk, second.snapshot.pk)
        self.assertEqual(Snapshot.objects.count(), 1)

    def test_unknown_version_and_truncated_bundle_are_refused(self):
        data = corpus_bundle("debian12", "minimal")
        with self.assertRaisesRegex(ImportRefused, "invalid bundle"):
            import_bundle(data.replace(b"ARIDI-BUNDLE 1 ", b"ARIDI-BUNDLE 9 ", 1),
                          create=True)
        with self.assertRaisesRegex(ImportRefused, "invalid bundle"):
            import_bundle(data[:len(data) // 2], create=True)
        with self.assertRaisesRegex(ImportRefused, "invalid bundle"):
            import_bundle(b"not a bundle\n", create=True)
        self.assertEqual(Snapshot.objects.count(), 0)

    @override_settings(ARIDI_MAX_BUNDLE_BYTES=1000)
    def test_size_limit(self):
        with self.assertRaisesRegex(ImportRefused, "larger than 1000 bytes"):
            import_bundle(corpus_bundle("debian12", "minimal"), create=True)

    def test_machine_matching(self):
        data = corpus_bundle("debian12", "minimal")
        core = interpret(core_bundle.parse(data))
        with self.assertRaisesRegex(ImportRefused, "name the machine or create it"):
            import_bundle(data)
        # Hostname alone is never trusted.
        same_name = Machine.objects.create(name=core.machine.hostname)
        with self.assertRaises(NeedsConfirmation) as caught:
            import_bundle(data)
        self.assertEqual(caught.exception.machine, same_name)
        stored = import_bundle(data, machine=same_name)
        same_name.refresh_from_db()
        if core.machine.machine_id:
            self.assertEqual(same_name.machine_id, core.machine.machine_id)
            other = Machine.objects.create(name="other")
            with self.assertRaisesRegex(ImportRefused, "belongs to machine"):
                import_bundle(corpus_bundle("debian12", "minimal"), machine=other)
        self.assertEqual(stored.snapshot.machine, same_name)

    @override_settings(ARIDI_RAW_RETENTION=2)
    def test_raw_bundle_retention(self):
        machine = Machine.objects.create(name="m")
        for name in ("debian12", "alpine320", "centos7"):
            import_bundle(corpus_bundle(name, "minimal"), machine=machine)
        kept = Snapshot.objects.filter(machine=machine).exclude(raw_bundle=None)
        self.assertEqual(kept.count(), 2)
        self.assertEqual(Snapshot.objects.filter(machine=machine).count(), 3)
        oldest = Snapshot.objects.filter(machine=machine).order_by("collected_at").first()
        self.assertIsNone(oldest.raw_bundle)
        self.assertIsNotNone(oldest.data)

    def test_import_command(self):
        path = CORPUS / "alpine320" / "minimal" / "bundle.aridi"
        out = io.StringIO()
        call_command("aridi_import", str(path), "--create", stdout=out)
        self.assertIn("imported:", out.getvalue())
        out = io.StringIO()
        call_command("aridi_import", str(path), stdout=out)
        self.assertIn("already imported:", out.getvalue())
        with self.assertRaisesRegex(CommandError, "no machine named"):
            call_command("aridi_import", str(path), "--machine", "nope")
        with self.assertRaisesRegex(CommandError, "cannot read"):
            call_command("aridi_import", "/nonexistent.aridi", "--create")


class ValidatorTest(TestCase):

    def test_ssh_targets(self):
        for good in ("aridi@host", "host", "aridi@10.0.0.1", "aridi@2001:db8::1",
                     "aridi@[2001:db8::1]", "a.b-c_d@srv-01.example.org"):
            self.assertTrue(SSH_TARGET.fullmatch(good), good)
        for bad in ("-oProxyCommand=x", "aridi@-oProxyCommand=x", "a b@host", "host;id",
                    "host$(id)", "@host", "aridi@host\n", "", "aridi@host -p 1"):
            self.assertFalse(SSH_TARGET.fullmatch(bad), bad)

    def test_model_validation(self):
        machine = Machine(name="x", ssh_target="-oProxyCommand=touch", proxy_jump="-J")
        with self.assertRaises(Exception) as caught:
            machine.full_clean()
        self.assertIn("ssh_target", caught.exception.message_dict)
        self.assertIn("proxy_jump", caught.exception.message_dict)

    def test_failed_collection_keeps_no_data(self):
        from aridi_central.inventory.importing import store_failure
        machine = Machine.objects.create(name="m")
        failed = store_failure(machine, Snapshot.Origin.SSH, "connection refused")
        self.assertEqual(failed.result, "failed")
        self.assertIsNone(failed.data)
        self.assertIsNone(machine.latest_snapshot())
