"""From raw bundle to snapshot: area registry and analyzer dispatch.

Every area of AREAS appears in the snapshot, always. An area without analyzer, without
sections in the bundle, or whose analyzer fails gets a Section with that status and a
reason; it never disappears (CLAUDE.md, rules 11 and 12).
"""

import importlib
import logging
import re
from dataclasses import dataclass, field

from aridi.model import Machine, Section, Snapshot, Status

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Area:
    name: str
    title: str
    group: str        # general, specific, volatile, carving
    volatile: bool = False


# Order of the 2019 report: general, specific, volatile, carving and neighbours.
AREAS = (
    Area("system", "System", "general"),
    Area("hardware", "Hardware", "general"),
    Area("packages", "Packages", "general"),
    Area("storage", "Storage", "general"),
    Area("permissions", "Dangerous permissions", "general"),
    Area("identity", "Identity and banners", "specific"),
    Area("users", "Users and groups", "specific"),
    Area("services", "Services", "specific"),
    Area("network", "Network", "specific"),
    Area("firewall", "Firewall", "specific"),
    Area("timesync", "Time synchronization", "specific"),
    Area("processes", "Processes", "volatile", volatile=True),
    Area("load", "CPU, memory and disk usage", "volatile", volatile=True),
    Area("sessions", "Sessions and logins", "volatile"),
    Area("connections", "Established connections", "volatile", volatile=True),
    Area("carving", "IPs and names in files", "carving"),
    Area("neighbours", "Neighbours", "carving", volatile=True),
)
AREA_NAMES = tuple(area.name for area in AREAS)


@dataclass
class AreaResult:
    """What an analyzer returns."""

    data: object
    relations: list = field(default_factory=list)
    status: Status = Status.OK
    reason: str | None = None


_parsers = {}


def register(area):
    """Decorator: register FUNC(sections) -> AreaResult as the analyzer of AREA.

    sections is a dict {name: RawSection} with the bundle sections "<area>.*".
    """
    if area not in AREA_NAMES:
        raise ValueError(f"unknown area {area!r}")

    def decorator(func):
        _parsers[area] = func
        return func
    return decorator


def _load_parsers():
    package = importlib.import_module("aridi.parsers")
    for area in AREA_NAMES:
        try:
            importlib.import_module(f"{package.__name__}.{area}")
        except ModuleNotFoundError as exc:
            if exc.name != f"{package.__name__}.{area}":
                raise


def _meta_text(bundle, name):
    raw = bundle.section(name)
    if raw is None or raw.status != "ok":
        return None
    return raw.text().strip() or None


_MACHINE_ID = re.compile(r"[0-9a-f]{32}")
_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")


def _machine(bundle):
    machine_id = None
    for name in ("meta.machine_id", "meta.dbus_machine_id"):
        value = _meta_text(bundle, name)
        if value and _MACHINE_ID.fullmatch(value):
            machine_id = value
            break
        if value:
            log.warning("ignoring malformed %s: %r", name, value[:40])
    return Machine(machine_id, _meta_text(bundle, "meta.hostname"))


def _collected_at(bundle):
    value = _meta_text(bundle, "meta.date_utc")
    if value and not _UTC.fullmatch(value):
        log.warning("ignoring malformed meta.date_utc: %r", value[:40])
        return None
    return value


def _area_section(area, bundle, parsers):
    prefix = area.name + "."
    sections = {name: raw for name, raw in bundle.sections.items()
                if name.startswith(prefix)}
    parser = parsers.get(area.name)
    if parser is None:
        return Section(Status.NO_PARSER, "no analyzer for this area yet",
                       volatile=area.volatile), []
    if not sections:
        return Section(Status.NOT_COLLECTED, "the bundle has no section of this area",
                       volatile=area.volatile), []
    try:
        result = parser(sections)
    except Exception as exc:  # an analyzer bug must not take the other areas down
        log.exception("analyzer of area %s failed", area.name)
        return Section(Status.ERROR, f"analyzer failed: {type(exc).__name__}: {exc}",
                       volatile=area.volatile), []
    return Section(result.status, result.reason, result.data, area.volatile), result.relations


def interpret(bundle, parsers=None):
    """Build the Snapshot of BUNDLE. PARSERS replaces the registry (tests)."""
    if parsers is None:
        _load_parsers()
        parsers = _parsers
    sections = {}
    relations = []
    for area in AREAS:
        sections[area.name], found = _area_section(area, bundle, parsers)
        relations.extend(found)
    return Snapshot(
        machine=_machine(bundle),
        collected_at=_collected_at(bundle),
        collector_version=bundle.collector_version,
        bundle_format=bundle.format_version,
        sections=sections,
        relations=relations,
    )
