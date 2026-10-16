"""Port names from src/aridi/data/services.csv (copied unchanged from legacy/services.csv,
format "name|port|description"; to be regenerated in TODO.md 7.1)."""

import functools
import logging
from importlib import resources

log = logging.getLogger(__name__)


@functools.cache
def _table():
    names = {}
    content = resources.files("aridi").joinpath("data/services.csv").read_text(encoding="utf-8")
    for number, line in enumerate(content.splitlines(), 1):
        fields = line.split("|")
        if len(fields) < 2 or not fields[1].strip().isdigit():
            if line.strip():
                log.debug("services.csv:%d: ignored line %r", number, line[:60])
            continue
        names.setdefault(int(fields[1]), fields[0].strip())
    return names


def name(port):
    """Service name of PORT, or None if unknown."""
    return _table().get(port)
