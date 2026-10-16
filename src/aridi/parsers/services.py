"""Area "services": systemd, SysV, OpenRC and runit in one list (TODO.md 3.8).

A systemctl binary without a running systemd (containers) gives "na" for systemd, never an
error (docs/MVP.md n.º 19).
"""

import re

from aridi.interpret import AreaResult, register
from aridi.model import Gap, Status
from aridi.parsers._common import first_line, text

_RC_LINK = re.compile(r"([SK])(\d\d)(.+)")
_OPENRC_STATUS = re.compile(r"^\s*(\S+)\s+\[\s*(\w[\w ]*?)\s*\]")
_RUNIT = re.compile(r"^(\w+): ([^:]+):")


def parse_systemd_units(content):
    """{unit: {load, active, sub, description}} from list-units --plain --no-legend."""
    units = {}
    for line in content.splitlines():
        line = line.strip()
        if line[:1] in ("●", "*", "×"):        # state mark of failed units, if any
            line = line[1:].strip()
        fields = line.split(None, 4)
        if len(fields) < 4:
            continue
        units[fields[0]] = {"load": fields[1], "active": fields[2], "sub": fields[3],
                            "description": fields[4] if len(fields) > 4 else ""}
    return units


def parse_unit_files(content):
    states = {}
    for line in content.splitlines():
        fields = line.split()
        if len(fields) >= 2:
            states[fields[0]] = fields[1]
    return states


def _systemd(sections):
    units_text = text(sections, "services.systemd_units")
    if units_text is None:
        return None
    files = parse_unit_files(text(sections, "services.systemd_unit_files") or "")
    services = []
    for unit, info in parse_systemd_units(units_text).items():
        if not unit.endswith(".service"):
            continue
        services.append({"manager": "systemd", "name": unit.removesuffix(".service"),
                         "active": info["active"], "sub": info["sub"],
                         "enabled": files.get(unit), "description": info["description"],
                         "runlevels": None})
    # Enabled services that are not loaded right now do not appear in list-units.
    listed = {s["name"] for s in services}
    for unit, state in files.items():
        name = unit.removesuffix(".service")
        if unit.endswith(".service") and name not in listed and "@" not in unit:
            services.append({"manager": "systemd", "name": name, "active": "inactive",
                             "sub": "dead", "enabled": state, "description": "",
                             "runlevels": None})
    return services


def _sysv(sections):
    chkconfig = text(sections, "services.chkconfig")
    rc_d = text(sections, "services.rc_d")
    if chkconfig is None and rc_d is None:
        return None
    runlevels = {}
    for line in (chkconfig or "").splitlines():
        fields = line.split()
        levels = [f.split(":")[0] for f in fields[1:] if f.endswith(":on") and ":" in f]
        if len(fields) >= 8 and all(":" in f for f in fields[1:8]):
            runlevels[fields[0]] = levels
    directory = None
    for line in (rc_d or "").splitlines():
        if line.endswith(":"):
            directory = re.search(r"rc([0-6S])\.d", line)
            continue
        match = _RC_LINK.fullmatch(line.strip())
        if directory and match and match.group(1) == "S":
            levels = runlevels.setdefault(match.group(3), [])
            if directory.group(1) not in levels:
                levels.append(directory.group(1))
        elif directory and match:
            runlevels.setdefault(match.group(3), [])
    return [{"manager": "sysv", "name": name, "active": None, "sub": None,
             "enabled": "enabled" if levels else "disabled", "description": "",
             "runlevels": sorted(levels)} for name, levels in sorted(runlevels.items())]


def _openrc(sections):
    levels_text = text(sections, "services.openrc_runlevels")
    if levels_text is None:
        return None
    runlevels, level = {}, None
    for line in levels_text.splitlines():
        if line.endswith(":"):
            level = line[:-1]
        elif level and line.strip():
            runlevels.setdefault(line.strip(), []).append(level)
    states = {}
    for line in (text(sections, "services.openrc_status") or "").splitlines():
        match = _OPENRC_STATUS.match(line)
        if match:
            states[match.group(1)] = match.group(2)
    names = sorted(set(runlevels) | set(states))
    return [{"manager": "openrc", "name": name, "active": states.get(name), "sub": None,
             "enabled": "enabled" if runlevels.get(name) else "disabled", "description": "",
             "runlevels": sorted(runlevels.get(name, []))} for name in names]


def openrc_levels(sections):
    """Runlevel names of /etc/runlevels, or None without OpenRC."""
    content = text(sections, "services.openrc_runlevels")
    if content is None:
        return None
    return [line[:-1] for line in content.splitlines() if line.endswith(":")]


def _runit(sections):
    content = text(sections, "services.runit")
    if content is None:
        return None
    services = []
    for line in content.splitlines():
        match = _RUNIT.match(line)
        if match:
            services.append({"manager": "runit", "name": match.group(2).rsplit("/", 1)[-1],
                             "active": match.group(1), "sub": None, "enabled": "enabled",
                             "description": "", "runlevels": None})
    return services


@register("services")
def parse(sections):
    gaps = []
    services, managers = [], []
    for manager, extract in (("systemd", _systemd), ("sysv", _sysv), ("openrc", _openrc),
                             ("runit", _runit)):
        found = extract(sections)
        if found is not None:
            managers.append(manager)
            services.extend(found)
    for name in ("services.systemd_units", "services.chkconfig", "services.openrc_status",
                 "services.runit"):
        raw = sections.get(name)
        if raw is not None and raw.status in ("denied", "timeout", "error"):
            gaps.append(Gap(name.removeprefix("services."), Status(raw.status),
                            raw.note or f"{name} {raw.status}"))
    if not managers:
        gaps.append(Gap("service manager", Status.NA,
                        "no running systemd, SysV, OpenRC nor runit found"))
    runlevel = first_line(text(sections, "services.runlevel"))
    data = {
        "init": first_line(text(sections, "services.init_comm")),
        "systemd_running": sections.get("services.systemd_units") is not None
        and sections["services.systemd_units"].status != "na",
        "runlevel": None if runlevel in (None, "unknown") else runlevel,
        "managers": managers,
        "openrc_runlevels": openrc_levels(sections),
        "services": services,
        "failed": sorted(s["name"] for s in services if s["active"] == "failed"),
    }
    return AreaResult(data, gaps=gaps)
