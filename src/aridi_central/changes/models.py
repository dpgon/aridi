"""Alerts, rule overrides and notification channels (TODO.md 6.2, 6.3 and 6.4).

The rules themselves are code (rules.py); the database only keeps how they are adjusted
per machine or group. Channels never hold secrets: a webhook names a URL that lives in
the environment (ARIDI_WEBHOOK_URL_<NAME>), like every other credential of the central.
"""

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.db import models
from django.db.models import Q

from aridi_central.changes.rules import BY_CODE, CHOICES, Severity
from aridi_central.inventory.models import Group, Machine, Snapshot


class RuleOverride(models.Model):
    """Silence a rule, or change its severity or threshold, for a machine or a group.

    The machine's override wins over its groups'. When several groups of a machine
    disagree, the one that alerts most wins: not silenced, the highest severity, the
    lowest threshold. A conflict never hides an alert.
    """

    rule = models.CharField(max_length=40, choices=CHOICES)
    machine = models.ForeignKey(Machine, null=True, blank=True, on_delete=models.CASCADE,
                                related_name="rule_overrides")
    group = models.ForeignKey(Group, null=True, blank=True, on_delete=models.CASCADE,
                              related_name="rule_overrides")
    silenced = models.BooleanField(default=False)
    severity = models.CharField(max_length=8, choices=Severity.choices, blank=True,
                                help_text="Empty: the rule's own severity")
    threshold = models.FloatField(null=True, blank=True,
                                  help_text="Empty: the rule's own threshold")

    class Meta:
        ordering = ["rule", "machine__name", "group__name"]
        constraints = [
            models.CheckConstraint(
                condition=(Q(machine__isnull=False, group__isnull=True)
                           | Q(machine__isnull=True, group__isnull=False)),
                name="override_machine_xor_group"),
            models.UniqueConstraint(fields=["rule", "machine"], condition=Q(group=None),
                                    name="override_unique_machine"),
            models.UniqueConstraint(fields=["rule", "group"], condition=Q(machine=None),
                                    name="override_unique_group"),
        ]

    def __str__(self):
        return f"{self.rule} for {self.machine or self.group}"

    def clean(self):
        if (self.machine_id is None) == (self.group_id is None):
            raise ValidationError("An override is for one machine or for one group.")
        rule = BY_CODE.get(self.rule)
        if self.threshold is not None and rule is not None and rule.threshold is None:
            raise ValidationError({"threshold": "This rule has no threshold."})
        if self.threshold is not None and self.threshold <= 0:
            raise ValidationError({"threshold": "The threshold must be positive."})


class Alert(models.Model):
    class State(models.TextChoices):
        NEW = "new", "new"
        SEEN = "seen", "seen"
        RESOLVED = "resolved", "resolved"

    machine = models.ForeignKey(Machine, on_delete=models.CASCADE, related_name="alerts")
    rule = models.CharField(max_length=40, choices=CHOICES, db_index=True)
    severity = models.CharField(max_length=8, choices=Severity.choices, db_index=True)
    # What the alert is about inside the rule (a user, a port…): an open alert with the
    # same machine, rule and key is not raised again.
    key = models.CharField(max_length=500)
    title = models.CharField(max_length=500)
    detail = models.JSONField(default=dict, blank=True)
    snapshot = models.ForeignKey(Snapshot, null=True, blank=True, on_delete=models.SET_NULL,
                                 related_name="alerts")
    previous = models.ForeignKey(Snapshot, null=True, blank=True, on_delete=models.SET_NULL,
                                 related_name="+")
    state = models.CharField(max_length=8, choices=State.choices, default=State.NEW,
                             db_index=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)
    changed_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True,
                                   on_delete=models.SET_NULL, related_name="+")
    note = models.TextField(blank=True)

    class Meta:
        ordering = ["-created_at", "-id"]
        indexes = [models.Index(fields=["machine", "rule", "key", "state"])]

    def __str__(self):
        return f"{self.machine}: {self.title}"

    @property
    def open(self):
        return self.state != self.State.RESOLVED


def validate_recipients(value):
    addresses = [a.strip() for a in value.split(",") if a.strip()]
    if not addresses:
        raise ValidationError("At least one address.")
    for address in addresses:
        validate_email(address)


class Channel(models.Model):
    class Kind(models.TextChoices):
        EMAIL = "email", "email"
        WEBHOOK = "webhook", "webhook (JSON POST)"

    name = models.CharField(max_length=100, unique=True)
    kind = models.CharField(max_length=8, choices=Kind.choices)
    target = models.CharField(
        max_length=1000,
        help_text="email: addresses separated by commas. webhook: the NAME of an "
                  "ARIDI_WEBHOOK_URL_<NAME> variable of the central (the URL itself is "
                  "never stored).")
    min_severity = models.CharField(max_length=8, choices=Severity.choices,
                                    default=Severity.MEDIUM)
    groups = models.ManyToManyField(Group, blank=True, related_name="channels",
                                    help_text="Only machines of these groups. None: all.")
    active = models.BooleanField(default=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name

    def clean(self):
        if self.kind == self.Kind.EMAIL:
            try:
                validate_recipients(self.target)
            except ValidationError as exc:
                raise ValidationError({"target": exc.messages}) from None
        elif self.kind == self.Kind.WEBHOOK:
            self.target = self.target.strip().lower()
            if self.target not in settings.ARIDI_WEBHOOKS:
                configured = ", ".join(sorted(settings.ARIDI_WEBHOOKS)) or "none"
                raise ValidationError({"target": f"No ARIDI_WEBHOOK_URL_{self.target.upper()}"
                                                 f" in the central (configured: "
                                                 f"{configured})."})

    @property
    def recipients(self):
        return [a.strip() for a in self.target.split(",") if a.strip()]


class Delivery(models.Model):
    """One alert sent through one channel, retried by the worker without blocking it."""

    class State(models.TextChoices):
        PENDING = "pending", "pending"
        SENT = "sent", "sent"
        FAILED = "failed", "failed"

    alert = models.ForeignKey(Alert, on_delete=models.CASCADE, related_name="deliveries")
    channel = models.ForeignKey(Channel, on_delete=models.CASCADE, related_name="deliveries")
    state = models.CharField(max_length=8, choices=State.choices, default=State.PENDING,
                             db_index=True)
    attempts = models.PositiveSmallIntegerField(default=0)
    next_try_at = models.DateTimeField(null=True, blank=True, db_index=True)
    sent_at = models.DateTimeField(null=True, blank=True)
    last_error = models.TextField(blank=True)

    class Meta:
        ordering = ["id"]
        constraints = [models.UniqueConstraint(fields=["alert", "channel"],
                                               name="delivery_unique")]

    def __str__(self):
        return f"{self.alert_id} via {self.channel} {self.state}"
