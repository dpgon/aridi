"""Port names from src/aridi/data/services.csv, generated from the IANA registry by
tools/build_services.py (TODO.md 7.1). Format: "#" header lines, then
"name|port|protocol|description"."""

import functools
import logging
from importlib import resources

log = logging.getLogger(__name__)


@functools.cache
def _table():
    names = {}
    content = resources.files("aridi").joinpath("data/services.csv").read_text(encoding="utf-8")
    for number, line in enumerate(content.splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        fields = line.split("|")
        if len(fields) < 3 or not fields[1].strip().isdigit() or not fields[0].strip():
            log.debug("services.csv:%d: ignored line %r", number, line[:60])
            continue
        names.setdefault((int(fields[1]), fields[2].strip().lower()), fields[0].strip())
    return names


def name(port, protocol="tcp"):
    """Service name of PORT for PROTOCOL ("tcp", "udp", "tcp6"…), or None if unknown."""
    return _table().get((port, protocol.lower().rstrip("6")))
