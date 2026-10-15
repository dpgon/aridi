"""Reader of raw bundles v1 written by collector/aridi-collect.sh (docs/FORMATO.md)."""

import re
from dataclasses import dataclass, field
from pathlib import Path

from aridi import BUNDLE_FORMAT_VERSION

FORMAT_VERSION = BUNDLE_FORMAT_VERSION

# Section states written by the collector.
STATUSES = frozenset({"ok", "denied", "missing", "na", "timeout", "error"})

_HEADER = re.compile(rb"ARIDI-BUNDLE (\d+) (\S+)")
_BOUNDARY = re.compile(rb"boundary ([0-9A-Za-z]{16,64})")
_NAME = r"[a-z0-9][a-z0-9_.-]{0,99}"
_BEGIN = re.compile(rf"begin ({_NAME})((?: [a-z_]+=\S*)*)")
_END = re.compile(rf"end ({_NAME}) status=([a-z]+) rc=(-|\d{{1,3}})")
_NOTE = re.compile(rf"note ({_NAME}) (.*)")
_CLOSE = re.compile(r"close sections=(\d+)")


class BundleError(Exception):
    """The data is not a valid raw bundle."""


class UnsupportedVersion(BundleError):
    """The bundle format version is not known by this core."""


class TruncatedBundle(BundleError):
    """The bundle ends before its closing line."""


@dataclass(frozen=True)
class RawSection:
    """One section of a raw bundle, as written by the collector."""

    name: str
    status: str
    rc: int | None
    content: bytes
    fields: dict = field(default_factory=dict)
    limit: int | None = None
    truncated: bool = False
    note: str = ""

    @property
    def size(self):
        """Bytes of content kept (after cutting to the limit)."""
        return len(self.content)

    def text(self):
        """Content as text; undecodable bytes are replaced, never dropped silently."""
        return self.content.decode("utf-8", errors="replace")


@dataclass(frozen=True)
class Bundle:
    format_version: int
    collector_version: str
    sections: dict

    def section(self, name):
        """The section NAME, or None if the bundle does not contain it."""
        return self.sections.get(name)


def _line_at(data, pos):
    """(line without newline, position after it); TruncatedBundle at end of data."""
    end = data.find(b"\n", pos)
    if end < 0:
        raise TruncatedBundle(f"unterminated line at byte {pos}")
    return data[pos:end], end + 1


def _ascii(line, pos):
    try:
        return line.decode("ascii")
    except UnicodeDecodeError:
        raise BundleError(f"non-ASCII control line at byte {pos}") from None


def _fields(text):
    result = {}
    for item in text.split():
        key, _, value = item.partition("=")
        result[key] = value
    return result


def parse(data):
    """Parse a raw bundle (bytes) and return a Bundle; raise BundleError if invalid."""
    if not data:
        raise BundleError("empty bundle")
    line, pos = _line_at(data, 0)
    header = _HEADER.fullmatch(line)
    if not header:
        raise BundleError("missing ARIDI-BUNDLE header")
    version = int(header.group(1))
    if version != FORMAT_VERSION:
        raise UnsupportedVersion(
            f"bundle format {version} is not supported (this core reads {FORMAT_VERSION})")
    collector_version = header.group(2).decode("ascii", errors="replace")

    line, pos = _line_at(data, pos)
    match = _BOUNDARY.fullmatch(line)
    if not match:
        raise BundleError("missing or invalid boundary line")
    marker = b"--" + match.group(1) + b" "

    sections = {}
    while True:
        start = pos
        line, pos = _line_at(data, pos)
        if not line.startswith(marker):
            raise BundleError(f"expected a boundary line at byte {start}")
        control = _ascii(line[len(marker):], start)

        close = _CLOSE.fullmatch(control)
        if close:
            declared = int(close.group(1))
            if declared != len(sections):
                raise BundleError(
                    f"close line declares {declared} sections, found {len(sections)}")
            if data[pos:].strip():
                raise BundleError(f"data after the close line at byte {pos}")
            return Bundle(version, collector_version, sections)

        begin = _BEGIN.fullmatch(control)
        if not begin:
            raise BundleError(f"expected 'begin' or 'close' at byte {start}: {control[:80]!r}")
        name = begin.group(1)
        if name in sections:
            raise BundleError(f"duplicate section {name!r}")
        fields = _fields(begin.group(2))

        # Content ends at the first "\n--<boundary> end <name> "; the collector always
        # adds that newline, so it is not part of the content.
        terminator = b"\n" + marker + f"end {name} ".encode("ascii")
        stop = data.find(terminator, pos)
        if stop < 0:
            raise TruncatedBundle(f"section {name!r} has no end line")
        content = data[pos:stop]
        line, pos = _line_at(data, stop + 1)
        end = _END.fullmatch(_ascii(line[len(marker):], stop + 1))
        if not end or end.group(1) != name:
            raise BundleError(f"invalid end line of section {name!r}")
        status = end.group(2)
        if status not in STATUSES:
            raise BundleError(f"unknown status {status!r} in section {name!r}")
        rc = None if end.group(3) == "-" else int(end.group(3))

        note = ""
        if data.startswith(marker + b"note ", pos):
            line, after = _line_at(data, pos)
            match = _NOTE.fullmatch(_ascii(line[len(marker):], pos))
            if not match or match.group(1) != name:
                raise BundleError(f"invalid note line of section {name!r}")
            note, pos = match.group(2), after

        limit = None
        if fields.get("limit", "").isdigit():
            limit = int(fields["limit"])
        truncated = limit is not None and len(content) > limit
        if truncated:
            content = content[:limit]
        sections[name] = RawSection(name, status, rc, content, fields, limit, truncated, note)


def read(path):
    """Read and parse the raw bundle at PATH."""
    return parse(Path(path).read_bytes())
