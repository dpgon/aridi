"""Sending alerts through external channels: email and JSON webhook (TODO.md 6.4).

Decided by the user on 2026-10-16: email (SMTP, django.core.mail) and a generic webhook
(JSON POST with urllib.request). A webhook of Slack or Mattermost receives the "text"
field. The worker sends deliveries in its own thread, with retries, so a destination
that is down never blocks the collections.

Titles carry text from the machines (user names, process names): the "text" of the
webhook is neutralized for chat markup, and the email subject has no line breaks.
"""

import json
import logging
import re
import smtplib
import urllib.error
import urllib.request
from datetime import timedelta

from django.conf import settings
from django.core.mail import send_mail
from django.db.models import F
from django.urls import reverse
from django.utils import timezone

from aridi_central.changes.models import Delivery
from aridi_central.changes.rules import BY_CODE

log = logging.getLogger(__name__)

CONTROL = re.compile(r"[\x00-\x1f\x7f]+")


class DeliveryError(Exception):
    """The channel did not take the alert; the message says why."""


def alert_url(alert):
    path = reverse("alert-detail", args=[alert.pk])
    return settings.ARIDI_BASE_URL.rstrip("/") + path if settings.ARIDI_BASE_URL else path


def one_line(text):
    return CONTROL.sub(" ", str(text)).strip()


def chat_text(text):
    """TEXT safe for Slack and Mattermost: no links, mentions or markup from machines."""
    text = one_line(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    # "@channel", "@here" or "@user" in a user name must not notify anyone.
    return text.replace("@", "@​")


def summary(alert):
    return f"[aridi] {alert.severity.upper()} {alert.machine.name}: {alert.title}"


def payload(alert):
    rule = BY_CODE.get(alert.rule)
    return {
        "text": f"{chat_text(summary(alert))} ({alert_url(alert)})",
        "alert": {
            "id": alert.pk,
            "url": alert_url(alert),
            "machine": alert.machine.name,
            "rule": alert.rule,
            "rule_title": rule.title if rule else alert.rule,
            "severity": alert.severity,
            "title": alert.title,
            "detail": alert.detail,
            "state": alert.state,
            "created_at": alert.created_at.isoformat(),
            "snapshot": alert.snapshot_id,
            "previous": alert.previous_id,
        },
    }


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A webhook that answers with a redirect has failed: the POST is not followed."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def send_webhook(channel, alert):
    url = settings.ARIDI_WEBHOOKS.get(channel.target)
    if not url:
        raise DeliveryError(f"ARIDI_WEBHOOK_URL_{channel.target.upper()} is not set")
    body = json.dumps(payload(alert), ensure_ascii=False).encode()
    request = urllib.request.Request(url, data=body, method="POST", headers={
        "Content-Type": "application/json", "User-Agent": "aridi-central"})
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(request, timeout=settings.ARIDI_WEBHOOK_TIMEOUT) as response:
            if not 200 <= response.status < 300:
                raise DeliveryError(f"HTTP {response.status}")
    except urllib.error.HTTPError as exc:
        raise DeliveryError(f"HTTP {exc.code}") from None
    except (urllib.error.URLError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        raise DeliveryError(f"cannot reach the webhook: {reason}") from None


def send_email(channel, alert):
    if not settings.EMAIL_HOST:
        raise DeliveryError("no SMTP server: ARIDI_EMAIL_HOST is not set")
    rule = BY_CODE.get(alert.rule)
    lines = [
        f"Machine:  {alert.machine.name}",
        f"Rule:     {rule.title if rule else alert.rule}",
        f"Severity: {alert.severity}",
        f"Raised:   {alert.created_at:%Y-%m-%d %H:%M:%S} UTC",
        "",
        alert.title,
        "",
    ]
    lines += [f"  {name}: {value}" for name, value in sorted(alert.detail.items())]
    lines += ["", f"See the alert and the comparison: {alert_url(alert)}"]
    try:
        send_mail(one_line(summary(alert))[:200], "\n".join(lines),
                  settings.DEFAULT_FROM_EMAIL, channel.recipients, fail_silently=False)
    except (smtplib.SMTPException, OSError, ValueError) as exc:   # ssl errors are OSError
        raise DeliveryError(f"email not sent: {exc}") from None


SENDERS = {"email": send_email, "webhook": send_webhook}


def backoff(attempts):
    """Wait before retry number ATTEMPTS: 1, 2, 4… minutes, at most one hour."""
    return timedelta(minutes=min(2 ** max(attempts - 1, 0), 60))


def deliver(delivery):
    """Try DELIVERY once and record the result."""
    try:
        SENDERS[delivery.channel.kind](delivery.channel, delivery.alert)
    except DeliveryError as exc:
        attempts = delivery.attempts + 1
        final = attempts >= settings.ARIDI_DELIVERY_ATTEMPTS
        Delivery.objects.filter(id=delivery.id).update(
            attempts=attempts, last_error=str(exc),
            state=Delivery.State.FAILED if final else Delivery.State.PENDING,
            next_try_at=None if final else timezone.now() + backoff(attempts))
        log.warning("alert %s via %s failed (attempt %d%s): %s", delivery.alert_id,
                    delivery.channel.name, attempts, ", giving up" if final else "", exc)
        return False
    Delivery.objects.filter(id=delivery.id).update(
        state=Delivery.State.SENT, sent_at=timezone.now(), attempts=F("attempts") + 1,
        last_error="", next_try_at=None)
    log.info("alert %s sent via %s", delivery.alert_id, delivery.channel.name)
    return True


def process_deliveries(limit=20):
    """Send the due deliveries. Each one is taken by moving its next try forward."""
    now = timezone.now()
    lease = now + timedelta(seconds=settings.ARIDI_WEBHOOK_TIMEOUT * 3 + 60)
    sent = 0
    due = (Delivery.objects.filter(state=Delivery.State.PENDING, next_try_at__lte=now)
           .order_by("next_try_at", "id").values_list("id", "next_try_at")[:limit])
    for delivery_id, next_try_at in list(due):
        taken = Delivery.objects.filter(id=delivery_id, state=Delivery.State.PENDING,
                                        next_try_at=next_try_at).update(next_try_at=lease)
        if not taken:
            continue
        delivery = Delivery.objects.select_related("alert__machine", "channel").get(
            id=delivery_id)
        sent += deliver(delivery)
    return sent
