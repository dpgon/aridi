"""Area "sessions": active sessions, recent logins and failed logins (TODO.md 3.14).

Sources, in order of preference: utmp/wtmp/btmp through utmpdump, wtmpdb and lastlog2
where wtmp no longer exists, who and last as fallback, and the sshd messages of the
journal or of the auth logs. Dates are handled in UTC, never with the locale of the
machine (2019 used setlocale).
"""

import ipaddress
import re
from datetime import datetime, timedelta, timezone

from aridi.interpret import AreaResult, register
from aridi.model import Gap, Relation, Role, Status
from aridi.parsers._common import first_line, text

USER_PROCESS, DEAD_PROCESS = "7", "8"
KEEP = 200          # most recent logins and failures kept in the snapshot

_BRACKETS = re.compile(r"\[(.*?)\]")
_ACCEPTED = re.compile(r"Accepted (\S+) for (\S+) from (\S+) port (\d+)")
_FAILED = re.compile(r"(?:Failed (\S+) for (?:invalid user )?(\S+)|Invalid user (\S*)) "
                     r"from (\S+) port (\d+)")
_JOURNAL_TIME = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:?\d{2})\s")
_SYSLOG_TIME = re.compile(r"^([A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2})\s")
_LAST_TIME = re.compile(r"([A-Z][a-z]{2} [A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2} \d{4})")


def parse_time(value):
    """UTC datetime from ISO 8601 or from "Thu Oct 15 16:26:03 2026 [UTC]"; None if not."""
    value = (value or "").strip()
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace(" ", "T", 1) if "T" not in value
                                        and value[:4].isdigit() else value)
    except ValueError:
        try:
            parsed = datetime.strptime(" ".join(value.split()[:5]), "%a %b %d %H:%M:%S %Y")
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    if parsed.year < 1990:          # utmp records without time
        return None
    return parsed.astimezone(timezone.utc)


def _iso(moment):
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ") if moment else None


def parse_utmpdump(content):
    """Records of utmpdump: type, pid, user, line, host, addr and time."""
    records = []
    for line in content.splitlines():
        fields = [f.strip() for f in _BRACKETS.findall(line)]
        if len(fields) < 8:
            continue
        records.append({"type": fields[0], "pid": fields[1], "user": fields[3],
                        "line": fields[4], "host": fields[5], "addr": fields[6],
                        "time": parse_time(fields[7])})
    return records


def parse_last(content):
    """Logins from "last -F -w" or "wtmpdb last -F": user, line, host and time."""
    logins = []
    for line in content.splitlines():
        fields = line.split()
        if len(fields) < 4 or fields[0] in ("reboot", "shutdown", "wtmp", "btmp", "wtmpdb"):
            continue
        match = _LAST_TIME.search(line)
        if not match:
            continue
        before = line[:match.start()].split()
        host = before[2] if len(before) >= 3 else ""
        logins.append({"user": before[0], "line": before[1] if len(before) > 1 else "",
                       "host": host, "time": parse_time(match.group(1)),
                       "active": "still logged in" in line})
    return logins


def parse_who(content):
    sessions = []
    for line in content.splitlines():
        fields = line.split()
        if len(fields) < 2:
            continue
        host = re.search(r"\(([^)]*)\)\s*$", line)
        when = parse_time(" ".join(fields[2:4])) if len(fields) >= 4 else None
        sessions.append({"user": fields[0], "line": fields[1],
                         "host": host.group(1) if host else "", "since": when})
    return sessions


def parse_sshd_messages(content, year=None):
    """(accepted, failed) sshd events from journal (short-iso) or syslog lines."""
    accepted, failed = [], []
    for line in content.splitlines():
        moment = None
        match = _JOURNAL_TIME.match(line)
        if match:
            moment = parse_time(match.group(1))
        else:
            match = _SYSLOG_TIME.match(line)
            if match and year:
                try:
                    moment = datetime.strptime(f"{year} {match.group(1)}", "%Y %b %d %H:%M:%S")
                    moment = moment.replace(tzinfo=timezone.utc)
                except ValueError:
                    moment = None
        ok = _ACCEPTED.search(line)
        if ok:
            accepted.append({"user": ok.group(2), "host": ok.group(3), "time": moment,
                             "method": ok.group(1)})
            continue
        bad = _FAILED.search(line)
        if bad:
            failed.append({"user": bad.group(2) or bad.group(3) or "", "host": bad.group(4),
                           "time": moment, "method": bad.group(1) or "invalid user"})
    return accepted, failed


def _ip(host):
    try:
        address = ipaddress.ip_address((host or "").split("%")[0])
    except ValueError:
        return None
    return None if address.is_loopback or address.is_unspecified else address


def _is_ip(host):
    try:
        ipaddress.ip_address((host or "").split("%")[0])
    except ValueError:
        return False
    return True


def _counts(events, now):
    if now is None:
        return None
    counts = {"day": 0, "week": 0, "month": 0}
    for event in events:
        moment = event.get("time")
        if moment is None or moment > now + timedelta(minutes=5):
            continue
        age = now - moment
        counts["day"] += age <= timedelta(days=1)
        counts["week"] += age <= timedelta(days=7)
        counts["month"] += age <= timedelta(days=30)
    return counts


def _order(event):
    return event.get("time") or datetime.min.replace(tzinfo=timezone.utc)


def _public(event):
    """EVENT for the snapshot: dates in ISO 8601, without the internal "_" keys."""
    return {key: (_iso(value) if isinstance(value, datetime) else value)
            for key, value in event.items() if not key.startswith("_")}


@register("sessions", uses=("meta",))
def parse(sections):
    now = parse_time(first_line(text(sections, "meta.date_utc")))
    sources = []

    active = None
    utmp = text(sections, "sessions.utmpdump_utmp")
    if utmp is not None:
        sources.append("utmp")
        active = [{"user": r["user"], "line": r["line"], "host": r["host"], "since": r["time"],
                   "_addr": r["addr"]}
                  for r in parse_utmpdump(utmp) if r["type"] == USER_PROCESS and r["user"]]
    elif text(sections, "sessions.who") is not None:
        sources.append("who")
        active = parse_who(text(sections, "sessions.who"))

    logins = []
    wtmp = text(sections, "sessions.utmpdump_wtmp")
    if wtmp is not None:
        sources.append("wtmp")
        logins = [{"user": r["user"], "line": r["line"], "host": r["host"], "time": r["time"],
                   "_addr": r["addr"]}
                  for r in parse_utmpdump(wtmp) if r["type"] == USER_PROCESS and r["user"]]
    else:
        for name, label in (("sessions.wtmpdb", "wtmpdb"), ("sessions.last", "last")):
            content = text(sections, name)
            if content is not None:
                sources.append(label)
                logins = parse_last(content)
                break

    failed = []
    btmp = text(sections, "sessions.utmpdump_btmp")
    if btmp is not None:
        sources.append("btmp")
        failed += [{"user": r["user"], "host": r["host"], "time": r["time"], "method": "btmp",
                    "_addr": r["addr"]}
                   for r in parse_utmpdump(btmp) if r["user"] or r["host"]]
    ssh_accepted = []
    for name in ("sessions.journal_sshd", "sessions.log_auth_log", "sessions.log_secure",
                 "sessions.log_messages"):
        content = text(sections, name)
        if content is None:
            continue
        sources.append(name.removeprefix("sessions."))
        accepted, refused = parse_sshd_messages(content, now.year if now else None)
        ssh_accepted += accepted
        failed += refused

    gaps = []
    for name in ("sessions.utmpdump_btmp", "sessions.journal_sshd", "sessions.utmpdump_wtmp"):
        raw = sections.get(name)
        if raw is not None and raw.status in ("denied", "timeout", "error"):
            gaps.append(Gap(name.removeprefix("sessions."), Status(raw.status),
                            raw.note or f"{name} {raw.status}"))

    relations, seen = [], set()
    for event, role in ([(e, Role.LOGIN_SOURCE) for e in logins + ssh_accepted + (active or [])]
                        + [(e, Role.FAILED_LOGIN_SOURCE) for e in failed]):
        # With "UseDNS yes" (CentOS 6 and 7) sshd records the resolved name as the host; the
        # utmp/wtmp record still has the peer address, which is what the map needs.
        address = _ip(event.get("host"))
        if address is None and not _is_ip(event.get("host")):
            address = _ip(event.get("_addr"))
        if address is not None and (address, role) not in seen:
            seen.add((address, role))
            relations.append(Relation(address, role, "sessions", event.get("user") or ""))

    data = {
        "sources": sources,
        "active": [_public(s) for s in active] if active is not None else None,
        "login_counts": _counts(logins or ssh_accepted, now),
        "failed_counts": _counts(failed, now),
        "logins": [_public(e) for e in sorted(logins, key=_order)[-KEEP:]],
        "ssh_accepted": [_public(e) for e in sorted(ssh_accepted, key=_order)[-KEEP:]],
        "failed": [_public(e) for e in sorted(failed, key=_order)[-KEEP:]],
        "failed_total": len(failed),
    }
    return AreaResult(data, relations=relations, gaps=gaps)
