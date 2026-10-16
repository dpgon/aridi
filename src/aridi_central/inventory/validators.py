"""Validation of the SSH fields of a machine.

They end up as arguments of ssh (collection/ssh.py, never through a shell): nothing may
start with "-" (it would be read as an option) or contain spaces or control characters.
"""

import re

from django.core.exceptions import ValidationError

_USER = r"[A-Za-z0-9._][A-Za-z0-9._-]{0,63}"
_HOST = (r"(?:[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?"   # name or IPv4
         r"|\[[0-9A-Fa-f:.]{2,45}\]|[0-9A-Fa-f:.]{2,45})")        # IPv6
SSH_TARGET = re.compile(rf"(?:{_USER}@)?{_HOST}")
PROXY_HOP = re.compile(rf"(?:{_USER}@)?{_HOST}(?::\d{{1,5}})?")


def validate_ssh_target(value):
    """user@host, host, user@[2001:db8::1]: no options, spaces or shell characters."""
    if not SSH_TARGET.fullmatch(value or ""):
        raise ValidationError("Use user@host (letters, digits, dots, dashes; IPv6 allowed).",
                              code="ssh_target")


def validate_proxy_jump(value):
    """Comma separated hops for "ssh -J": [user@]host[:port]."""
    if not value:
        return
    for hop in value.split(","):
        if not PROXY_HOP.fullmatch(hop):
            raise ValidationError(f"Invalid jump host {hop!r}: use [user@]host[:port].",
                                  code="proxy_jump")
