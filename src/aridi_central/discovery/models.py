"""Authorized networks and scan results (TODO.md 7.2).

Only an active AuthorizedNetwork can be scanned, and the scanner checks the perimeter
again before every connection (scanner.py). Scanning is off unless ARIDI_SCAN_ENABLED=1.
"""

import ipaddress

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models


def validate_cidr(value):
    """A network in CIDR form, without host bits, no larger than the configured maximum."""
    try:
        network = ipaddress.ip_network(value.strip(), strict=True)
    except ValueError as exc:
        raise ValidationError(f"Not a network in CIDR form: {exc}") from None
    largest = (settings.ARIDI_SCAN_MAX_PREFIX_V4 if network.version == 4
               else settings.ARIDI_SCAN_MAX_PREFIX_V6)
    if network.prefixlen < largest:
        raise ValidationError(f"Too large: the largest IPv{network.version} network allowed "
                              f"is /{largest} (ARIDI_SCAN_MAX_PREFIX_V{network.version}).")
    if network.is_multicast or network.is_unspecified:
        raise ValidationError("Multicast and unspecified addresses cannot be scanned.")


class AuthorizedNetwork(models.Model):
    class Ports(models.TextChoices):
        COMMON = "common", "the most common TCP ports"
        ALL = "all", "every TCP port (1-65535)"

    cidr = models.CharField(max_length=64, unique=True, validators=[validate_cidr],
                            help_text="e.g. 192.0.2.0/24 or 2001:db8::/120")
    description = models.TextField(help_text="Whose network it is and why it may be scanned")
    ports = models.CharField(max_length=8, choices=Ports.choices, default=Ports.COMMON)
    active = models.BooleanField(default=True)
    authorized_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True,
                                      on_delete=models.SET_NULL, related_name="+")
    authorized_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["cidr"]

    def __str__(self):
        return self.cidr

    def save(self, *args, **kwargs):
        self.cidr = str(ipaddress.ip_network(self.cidr.strip(), strict=True))
        super().save(*args, **kwargs)

    @property
    def network(self):
        return ipaddress.ip_network(self.cidr)


class ScanResult(models.Model):
    """An open port found by a scan. Closed and filtered ports are not stored."""

    network = models.ForeignKey(AuthorizedNetwork, on_delete=models.CASCADE,
                                related_name="results")
    job = models.ForeignKey("collection.Job", null=True, on_delete=models.SET_NULL,
                            related_name="scan_results")
    ip = models.GenericIPAddressField(db_index=True)
    protocol = models.CharField(max_length=8, default="tcp")
    port = models.PositiveIntegerField()
    state = models.CharField(max_length=8, default="open")
    service = models.CharField(max_length=64, blank=True)
    scanned_at = models.DateTimeField(db_index=True)

    class Meta:
        ordering = ["-scanned_at", "ip", "port"]

    def __str__(self):
        return f"{self.ip} {self.protocol}/{self.port} {self.state}"
