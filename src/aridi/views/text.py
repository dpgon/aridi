"""Human-readable report of a snapshot: summary or detail per area, then the gaps.

Every string that comes from the inspected machine is untrusted: clean() escapes control
characters, so a banner with ANSI sequences cannot rewrite the terminal.
"""

import re

from aridi.interpret import AREAS
from aridi.model import Status

# Area renderers registered by phase 3: FUNC(data, detail) -> list of lines.
_renderers = {}

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")

STATUS_TEXT = {
    Status.OK: "ok",
    Status.DENIED: "denied (no permission)",
    Status.MISSING: "missing tool",
    Status.NA: "not applicable",
    Status.TIMEOUT: "timed out",
    Status.ERROR: "error",
    Status.NOT_COLLECTED: "not collected",
    Status.NO_PARSER: "no analyzer",
}


def renderer(area):
    """Decorator: register the text renderer of AREA."""
    def decorator(func):
        _renderers[area] = func
        return func
    return decorator


def clean(value):
    """Text safe for a terminal: control characters become \\xNN; tabs and newlines too."""
    text = "" if value is None else str(value)
    return _CONTROL.sub(lambda m: f"\\x{ord(m.group()):02x}", text.replace("\t", "\\t")
                        .replace("\n", "\\n"))


def _title(text, char="="):
    return [text, char * len(text)]


def _area_lines(area, section, detail):
    lines = _title(area.title + (" (volatile)" if area.volatile else ""), "-")
    if section.status != Status.OK:
        lines.append(f"  [{STATUS_TEXT[section.status]}] {clean(section.reason)}")
        return lines
    render = _renderers.get(area.name)
    if render is None:
        lines.append("  (no text view for this area yet)")
        return lines
    lines.extend("  " + clean(line) for line in render(section.data, detail))
    return lines


def render(snapshot, detail=False):
    """The report as a string."""
    lines = _title(f"aridi report: {clean(snapshot.machine.hostname or '(unknown host)')}")
    lines += [
        f"Machine id:   {clean(snapshot.machine.machine_id or '(unknown)')}",
        f"Collected at: {clean(snapshot.collected_at or '(unknown)')}",
        f"Collector:    {clean(snapshot.collector_version)} "
        f"(bundle format {snapshot.bundle_format}, snapshot schema {snapshot.schema_version})",
        f"Result:       {'complete' if not snapshot.gaps() else 'with gaps'}",
        f"Level:        {'detail' if detail else 'summary'}",
        "",
    ]
    for area in AREAS:
        section = snapshot.sections.get(area.name)
        if section is None:
            continue
        lines += _area_lines(area, section, detail) + [""]

    gaps = snapshot.gaps()
    lines += _title("What could not be seen")
    if not gaps:
        lines.append("Nothing: every area was collected and analyzed.")
    else:
        titles = {area.name: area.title for area in AREAS}
        width = max(len(titles.get(name, name)) for name, _ in gaps)
        for name, section in gaps:
            lines.append(f"{titles.get(name, name):<{width}}  {section.status.value:<13}  "
                         f"{clean(section.reason)}")
    return "\n".join(lines) + "\n"
