"""manage.py aridi_import FILE [--machine NAME | --create]: import a local collection."""

from django.core.management.base import BaseCommand, CommandError

from aridi_central.inventory.importing import ImportRefused, import_bundle
from aridi_central.inventory.models import Machine


class Command(BaseCommand):
    help = "Import a raw bundle made with collector/aridi-collect.sh (TODO.md 5.3)."

    def add_arguments(self, parser):
        parser.add_argument("file", help="raw bundle file")
        target = parser.add_mutually_exclusive_group()
        target.add_argument("--machine", help="name of the machine it belongs to")
        target.add_argument("--create", action="store_true",
                            help="create a machine named after the hostname if none matches")

    def handle(self, *args, **options):
        machine = None
        if options["machine"]:
            machine = Machine.objects.filter(name=options["machine"]).first()
            if machine is None:
                raise CommandError(f"no machine named {options['machine']!r}")
        try:
            with open(options["file"], "rb") as handle:
                data = handle.read()
        except OSError as exc:
            raise CommandError(f"cannot read {options['file']}: {exc.strerror or exc}") from None
        try:
            stored = import_bundle(data, machine=machine, create=options["create"])
        except ImportRefused as exc:
            raise CommandError(str(exc)) from None
        snapshot = stored.snapshot
        state = "imported" if stored.created else "already imported"
        when = snapshot.collected_at.strftime("%Y-%m-%d %H:%M:%SZ")
        self.stdout.write(f"{state}: {snapshot.machine.name} {when} {snapshot.result} "
                          f"(snapshot {snapshot.pk})")
