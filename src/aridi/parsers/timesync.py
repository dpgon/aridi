"""Area "timesync": time synchronization service and servers (TODO.md 3.11).

Recovered from 2019 gathering2.py:260. Server names are kept as text, never resolved;
only IP literals become ntp_server relations.
"""

import ipaddress
import re

from aridi.interpret import AreaResult, register
from aridi.model import Gap, Relation, Role, Status
from aridi.parsers._common import text

_CHRONY_SOURCE = re.compile(r"^\s*(server|pool|peer)\s+(\S+)", re.M)
_NTP_SOURCE = re.compile(r"^\s*(server|pool|peer)\s+(\S+)", re.M)
# chronyc -n sources: "^* 192.0.2.124   2  6  377  12  +10us[ +12us] +/- 20ms"
_CHRONYC = re.compile(r"^([\^=#])([*+\-?x~ ])\s+(\S+)", re.M)
_NTPQ = re.compile(r"^([*+#ox.\- ])(\S+)\s", re.M)


def parse_timesyncd(content):
    """NTP= and FallbackNTP= of timesyncd.conf and its drop-ins (last value wins)."""
    values = {"NTP": [], "FallbackNTP": []}
    section = None
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
        elif section == "Time" and "=" in line and not line.startswith(("#", ";")):
            key, _, value = line.partition("=")
            if key.strip() in values:
                values[key.strip()] = value.split()
    return values


def _is_ip(value):
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


@register("timesync")
def parse(sections):
    gaps, services = [], []
    configured, in_use = [], []

    chrony_conf = text(sections, "timesync.chrony_conf") or text(
        sections, "timesync.chrony_conf_debian")
    chronyc = text(sections, "timesync.chronyc")
    if chrony_conf is not None or chronyc is not None:
        services.append("chrony")
        configured += [{"service": "chrony", "kind": kind, "server": server}
                       for kind, server in _CHRONY_SOURCE.findall(chrony_conf or "")]
        for _mode, state, server in _CHRONYC.findall(chronyc or ""):
            in_use.append({"service": "chrony", "server": server,
                           "selected": state == "*"})

    ntp_conf = text(sections, "timesync.ntp_conf")
    ntpq = text(sections, "timesync.ntpq")
    if ntp_conf is not None or ntpq is not None:
        services.append("ntpd")
        configured += [{"service": "ntpd", "kind": kind, "server": server}
                       for kind, server in _NTP_SOURCE.findall(ntp_conf or "")]
        for line in (ntpq or "").splitlines()[2:]:
            match = _NTPQ.match(line)
            if match:
                in_use.append({"service": "ntpd", "server": match.group(2),
                               "selected": match.group(1) == "*"})

    timesyncd = text(sections, "timesync.timesyncd_conf")
    timedatectl = text(sections, "timesync.timedatectl")
    if timesyncd is not None:
        services.append("systemd-timesyncd")
        values = parse_timesyncd(timesyncd)
        configured += [{"service": "systemd-timesyncd", "kind": "server", "server": server}
                       for server in values["NTP"]]
        configured += [{"service": "systemd-timesyncd", "kind": "fallback", "server": server}
                       for server in values["FallbackNTP"]]
    if timedatectl:
        show = dict(line.partition("=")[::2] for line in timedatectl.splitlines() if "=" in line)
        if show.get("ServerAddress"):
            in_use.append({"service": "systemd-timesyncd", "server": show["ServerAddress"],
                           "name": show.get("ServerName") or None, "selected": True})

    # A query only matters for a service that is configured (timedatectl fails where
    # timesyncd is not the time service, e.g. Rocky with chrony).
    queries = {"timesync.chronyc": "chrony", "timesync.ntpq": "ntpd",
               "timesync.timedatectl": "systemd-timesyncd"}
    for name, service in queries.items():
        raw = sections.get(name)
        if service in services and raw is not None and raw.status in ("denied", "timeout",
                                                                       "error"):
            gaps.append(Gap(name.removeprefix("timesync."), Status(raw.status),
                            raw.note or f"{name} {raw.status}"))
    if not services:
        gaps.append(Gap("time service", Status.NA, "no chrony, ntpd nor timesyncd"))

    relations = []
    seen = set()
    for item in configured + in_use:
        server = item["server"]
        if _is_ip(server) and server not in seen:
            seen.add(server)
            relations.append(Relation(server, Role.NTP_SERVER, "timesync", item["service"]))
    data = {"services": services, "configured": configured, "in_use": in_use}
    return AreaResult(data, relations=relations, gaps=gaps)
