"""Email and webhook channels (TODO.md 6.4): locmem email, a local http.server for the
webhook, and a destination that hangs while the worker keeps collecting."""

import json
import threading
import time
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from django.core import mail
from django.core.exceptions import ValidationError
from django.db import connection
from django.test import TestCase, TransactionTestCase, override_settings
from django.utils import timezone

from aridi_central.changes.channels import chat_text, process_deliveries
from aridi_central.changes.evaluate import raise_alert
from aridi_central.changes.models import Alert, Channel, Delivery
from aridi_central.changes.rules import BY_CODE, Finding
from aridi_central.collection.models import Job
from aridi_central.collection.ssh import Result
from aridi_central.collection.worker import Worker, enqueue
from aridi_central.inventory.models import Group, Machine
from aridi_central.testing import CORPUS

BUNDLE = (CORPUS / "debian12" / "minimal" / "bundle.aridi").read_bytes()


class Receiver:
    """A local webhook: records the JSON bodies; answers STATUS after DELAY seconds."""

    def __init__(self, status=200, delay=0):
        self.bodies = []
        receiver = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers["Content-Length"])
                receiver.bodies.append((self.headers["Content-Type"],
                                        json.loads(self.rfile.read(length))))
                time.sleep(delay)
                self.send_response(status)
                self.end_headers()

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/hook"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def alert(machine, severity="high", title="New user mallory with login shell /bin/bash"):
    return raise_alert(machine, BY_CODE["privileged_user"], severity,
                       Finding("mallory:new", title, {"user": "mallory"}))


@override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
                   EMAIL_HOST="smtp.example", ARIDI_BASE_URL="https://aridi.example")
class ChannelTest(TestCase):

    def setUp(self):
        self.machine = Machine.objects.create(name="srv", ssh_target="aridi@srv")

    def test_email(self):
        Channel.objects.create(name="ops", kind="email", target="ops@example.org, b@example.org")
        alert(self.machine)
        self.assertEqual(process_deliveries(), 1)
        [message] = mail.outbox
        self.assertEqual(message.to, ["ops@example.org", "b@example.org"])
        self.assertEqual(message.subject, "[aridi] HIGH srv: New user mallory with login shell "
                                          "/bin/bash")
        self.assertIn("https://aridi.example/alerts/", message.body)
        self.assertEqual(Delivery.objects.get().state, Delivery.State.SENT)

    def test_subject_without_line_breaks(self):
        Channel.objects.create(name="ops", kind="email", target="ops@example.org")
        alert(self.machine, title="New user evil\r\nBcc: x@example.org")
        process_deliveries()
        self.assertNotIn("\n", mail.outbox[0].subject)
        self.assertEqual(mail.outbox[0].bcc, [])

    def test_webhook_receives_the_json(self):
        receiver = Receiver()
        self.addCleanup(receiver.close)
        with self.settings(ARIDI_WEBHOOKS={"chat": receiver.url}):
            Channel.objects.create(name="chat", kind="webhook", target="chat")
            created = alert(self.machine, title="New user <!channel> @here")
            self.assertEqual(process_deliveries(), 1)
        [(content_type, body)] = receiver.bodies
        self.assertEqual(content_type, "application/json")
        self.assertEqual(body["alert"]["id"], created.pk)
        self.assertEqual(body["alert"]["machine"], "srv")
        self.assertEqual(body["alert"]["rule"], "privileged_user")
        self.assertEqual(body["alert"]["severity"], "high")
        self.assertEqual(body["alert"]["detail"], {"user": "mallory"})
        self.assertEqual(body["alert"]["url"], f"https://aridi.example/alerts/{created.pk}/")
        # Chat markup from a machine is neutralized in "text"; "alert" keeps it as data.
        self.assertNotIn("<!channel>", body["text"])
        self.assertNotIn("@here", body["text"])
        self.assertEqual(body["alert"]["title"], "New user <!channel> @here")

    def test_failure_is_retried_then_given_up(self):
        receiver = Receiver(status=500)
        self.addCleanup(receiver.close)
        with self.settings(ARIDI_WEBHOOKS={"chat": receiver.url}, ARIDI_DELIVERY_ATTEMPTS=2):
            Channel.objects.create(name="chat", kind="webhook", target="chat")
            alert(self.machine)
            self.assertEqual(process_deliveries(), 0)
            delivery = Delivery.objects.get()
            self.assertEqual((delivery.state, delivery.attempts, delivery.last_error),
                             (Delivery.State.PENDING, 1, "HTTP 500"))
            self.assertGreater(delivery.next_try_at, timezone.now())
            self.assertEqual(process_deliveries(), 0)            # not due yet
            Delivery.objects.update(next_try_at=timezone.now() - timedelta(seconds=1))
            process_deliveries()
        delivery.refresh_from_db()
        self.assertEqual((delivery.state, delivery.attempts), (Delivery.State.FAILED, 2))
        self.assertEqual(len(receiver.bodies), 2)

    def test_unreachable_and_redirect(self):
        receiver = Receiver(status=302)
        self.addCleanup(receiver.close)
        with self.settings(ARIDI_WEBHOOKS={"gone": "http://127.0.0.1:9/", "moved": receiver.url}):
            Channel.objects.create(name="gone", kind="webhook", target="gone")
            Channel.objects.create(name="moved", kind="webhook", target="moved")
            alert(self.machine)
            process_deliveries()
        errors = dict(Delivery.objects.values_list("channel__name", "last_error"))
        self.assertIn("cannot reach the webhook", errors["gone"])
        self.assertEqual(errors["moved"], "HTTP 302")

    def test_email_without_smtp(self):
        Channel.objects.create(name="ops", kind="email", target="ops@example.org")
        alert(self.machine)
        with self.settings(EMAIL_HOST=""):
            process_deliveries()
        self.assertIn("ARIDI_EMAIL_HOST", Delivery.objects.get().last_error)

    def test_filters_by_severity_and_group(self):
        web = Group.objects.create(name="web")
        Channel.objects.create(name="high-only", kind="email", target="a@example.org",
                               min_severity="high")
        only_web = Channel.objects.create(name="web-team", kind="email",
                                          target="b@example.org", min_severity="low")
        only_web.groups.add(web)
        Channel.objects.create(name="off", kind="email", target="c@example.org",
                               min_severity="low", active=False)
        alert(self.machine, severity="medium")
        self.assertEqual(Delivery.objects.count(), 0)
        self.machine.groups.add(web)
        Alert.objects.all().delete()
        alert(self.machine, severity="high")
        self.assertEqual(sorted(Delivery.objects.values_list("channel__name", flat=True)),
                         ["high-only", "web-team"])

    def test_channel_validation(self):
        with self.settings(ARIDI_WEBHOOKS={"chat": "https://chat.example/hook"}):
            Channel(name="a", kind="webhook", target="CHAT").full_clean()
            with self.assertRaises(ValidationError):
                Channel(name="b", kind="webhook", target="https://evil.example/").full_clean()
        with self.assertRaises(ValidationError):
            Channel(name="c", kind="email", target="not an address").full_clean()

    def test_chat_text(self):
        self.assertEqual(chat_text("a <b> & @c\n"), "a &lt;b&gt; &amp; @​c")


class NotBlockingTest(TransactionTestCase):

    def test_a_hanging_webhook_does_not_delay_collections(self):
        receiver = Receiver(delay=4)
        self.addCleanup(receiver.close)
        machine = Machine.objects.create(name="srv", ssh_target="aridi@srv")
        with self.settings(ARIDI_WEBHOOKS={"chat": receiver.url}, ARIDI_WEBHOOK_TIMEOUT=2):
            Channel.objects.create(name="chat", kind="webhook", target="chat")
            alert(machine)
            worker = Worker(poll_seconds=0.2, shutdown_grace=5,
                            collect=lambda m: Result(True, bundle=BUNDLE))
            thread = threading.Thread(target=worker.run_forever)
            thread.start()
            try:
                deadline = time.monotonic() + 1.5
                while not receiver.bodies:            # the delivery is hanging now
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.05)
                [job] = enqueue([machine])
                deadline = time.monotonic() + 1.5     # well before the webhook times out
                while Job.objects.get(pk=job.pk).state != Job.State.DONE:
                    self.assertLess(time.monotonic(), deadline, "the collection waited")
                    time.sleep(0.05)
                deadline = time.monotonic() + 10
                while Delivery.objects.get().attempts == 0:
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.1)
            finally:
                worker.stop.set()
                thread.join(15)
                connection.close()
        delivery = Delivery.objects.get()
        self.assertEqual(delivery.state, Delivery.State.PENDING)
        self.assertIn("timed out", delivery.last_error)
