"""Snapshot model v1: what the core produces from a raw bundle (docs/FORMATO.md)."""

import ipaddress
import json
from dataclasses import dataclass, field
from enum import StrEnum

SCHEMA_VERSION = 1


class SnapshotError(ValueError):
    """The data is not a valid snapshot v1."""


class Status(StrEnum):
    """State of an area in the snapshot."""

    OK = "ok"
    DENIED = "denied"            # no permission to read the source
    MISSING = "missing"          # the tool does not exist on the machine
    NA = "na"                    # does not apply to this machine
    TIMEOUT = "timeout"          # the section ran out of time
    ERROR = "error"              # the collector or the analyzer failed
    NOT_COLLECTED = "not_collected"  # the bundle has no section of this area
    NO_PARSER = "no_parser"      # this core has no analyzer for the area yet


class Role(StrEnum):
    """Role of an IP address in relation to the machine. Codes, never sentences."""

    LOCAL = "local"
    DNS_SERVER = "dns_server"
    NTP_SERVER = "ntp_server"
    LOGIN_SOURCE = "login_source"
    FAILED_LOGIN_SOURCE = "failed_login_source"
    FW_ALLOWED_IN = "fw_allowed_in"
    FW_ALLOWED_OUT = "fw_allowed_out"
    PEER_IN = "peer_in"
    PEER_OUT = "peer_out"
    NAMED_IN_FILE = "named_in_file"
    NEIGHBOUR = "neighbour"
    SCAN_OPEN_PORT = "scan_open_port"


# States that are not a gap: the data is there, or it does not apply to this machine.
NOT_A_GAP = frozenset({Status.OK, Status.NA})


class Outcome(StrEnum):
    """Result of a snapshot as a whole."""

    COMPLETE = "complete"
    GAPS = "gaps"


@dataclass(frozen=True)
class Relation:
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address
    role: Role
    source: str              # area that found it
    detail: str = ""

    def __post_init__(self):
        try:
            object.__setattr__(self, "ip", ipaddress.ip_address(self.ip))
            object.__setattr__(self, "role", Role(self.role))
        except ValueError as exc:
            raise SnapshotError(f"invalid relation: {exc}") from None

    def to_dict(self):
        return {"ip": str(self.ip), "role": self.role.value, "source": self.source,
                "detail": self.detail}


def _status(value):
    try:
        return Status(value)
    except ValueError:
        raise SnapshotError(f"unknown status {value!r}") from None


@dataclass
class Gap:
    """A part of an area that could not be seen, while the rest of the area could."""

    item: str
    status: Status
    reason: str

    def __post_init__(self):
        self.status = _status(self.status)

    def to_dict(self):
        return {"item": self.item, "status": self.status.value, "reason": self.reason}


@dataclass
class Section:
    status: Status
    reason: str | None = None
    data: object = None
    volatile: bool = False
    gaps: list = field(default_factory=list)

    def __post_init__(self):
        self.status = _status(self.status)

    def to_dict(self):
        return {"status": self.status.value, "reason": self.reason, "data": self.data,
                "volatile": self.volatile, "gaps": [g.to_dict() for g in self.gaps]}


@dataclass
class Machine:
    machine_id: str | None
    hostname: str | None


@dataclass
class Snapshot:
    machine: Machine
    collected_at: str | None
    collector_version: str
    bundle_format: int
    sections: dict = field(default_factory=dict)
    relations: list = field(default_factory=list)
    schema_version: int = SCHEMA_VERSION

    def gaps(self):
        """(area, item, status, reason) of what could not be seen, in area order.

        item is None for a whole area. Areas and items in "na" are not gaps.
        """
        found = []
        for name, section in self.sections.items():
            if section.status not in NOT_A_GAP:
                found.append((name, None, section.status, section.reason))
            found.extend((name, g.item, g.status, g.reason) for g in section.gaps
                         if g.status not in NOT_A_GAP)
        return found

    def outcome(self):
        return Outcome.GAPS if self.gaps() else Outcome.COMPLETE

    def to_dict(self):
        return {
            "schema_version": self.schema_version,
            "machine": {"machine_id": self.machine.machine_id,
                        "hostname": self.machine.hostname},
            "collected_at": self.collected_at,
            "collector_version": self.collector_version,
            "bundle_format": self.bundle_format,
            "outcome": self.outcome().value,
            "sections": {name: s.to_dict() for name, s in self.sections.items()},
            "relations": [r.to_dict() for r in self.relations],
        }

    def to_json(self):
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False) + "\n"

    @classmethod
    def from_dict(cls, data):
        if not isinstance(data, dict):
            raise SnapshotError("a snapshot must be a JSON object")
        version = data.get("schema_version")
        if version != SCHEMA_VERSION:
            raise SnapshotError(
                f"snapshot schema {version!r} is not supported (this core reads "
                f"{SCHEMA_VERSION})")
        try:
            machine = data["machine"]
            return cls(
                machine=Machine(machine.get("machine_id"), machine.get("hostname")),
                collected_at=data.get("collected_at"),
                collector_version=data["collector_version"],
                bundle_format=data["bundle_format"],
                sections={name: Section(s["status"], s.get("reason"), s.get("data"),
                                        bool(s.get("volatile", False)),
                                        [Gap(g["item"], g["status"], g["reason"])
                                         for g in s.get("gaps", [])])
                          for name, s in data["sections"].items()},
                relations=[Relation(r["ip"], r["role"], r["source"], r.get("detail", ""))
                           for r in data.get("relations", [])],
            )
        except (KeyError, TypeError, AttributeError) as exc:
            raise SnapshotError(f"malformed snapshot: {exc!r}") from None

    @classmethod
    def from_json(cls, text):
        try:
            return cls.from_dict(json.loads(text))
        except json.JSONDecodeError as exc:
            raise SnapshotError(f"not JSON: {exc}") from None
