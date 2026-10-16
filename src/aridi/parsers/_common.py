"""Helpers shared by the analyzers."""

from aridi.model import Gap, Status


def text(sections, name):
    """Content of section NAME as text if it was collected with status ok, else None."""
    raw = sections.get(name)
    if raw is None or raw.status != "ok":
        return None
    return raw.text()


def first_line(value):
    """First non-empty line of VALUE, stripped, or None."""
    if value is None:
        return None
    for line in value.splitlines():
        if line.strip():
            return line.strip()
    return None


def gap(sections, item, names, reason):
    """Gap for ITEM, with the most telling status among the sections NAMES.

    A section that was denied, timed out or failed explains the gap better than one that
    does not exist; if none exists, the status is error with REASON.
    """
    for wanted in (Status.DENIED, Status.TIMEOUT, Status.MISSING, Status.ERROR):
        for name in names:
            raw = sections.get(name)
            if raw is not None and raw.status == wanted.value:
                note = f": {raw.note}" if raw.note else ""
                return Gap(item, wanted, f"{name} {raw.status}{note}")
    return Gap(item, Status.ERROR, reason)


def user_names(sections):
    """{uid: name} from the users.passwd section (the analyzer must use "users")."""
    names = {}
    for line in (text(sections, "users.passwd") or "").splitlines():
        fields = line.split(":")
        if len(fields) >= 3 and fields[2].isdigit():
            names.setdefault(int(fields[2]), fields[0])
    return names
