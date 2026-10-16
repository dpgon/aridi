"""manage.py aridi_worker: the collection worker (TODO.md 5.5). Stops cleanly on SIGTERM."""

import signal

from django.core.management.base import BaseCommand

from aridi_central.collection.worker import Worker


class Command(BaseCommand):
    help = "Run queued and scheduled collections over SSH."

    def add_arguments(self, parser):
        parser.add_argument("--poll", type=float, default=5.0,
                            help="seconds between queue checks (default 5)")
        parser.add_argument("--max-ssh", type=int, default=None,
                            help="concurrent SSH sessions (default ARIDI_MAX_SSH)")

    def handle(self, *args, **options):
        worker = Worker(max_ssh=options["max_ssh"], poll_seconds=options["poll"])

        def stop(signum, frame):
            worker.stop.set()

        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        worker.run_forever()
