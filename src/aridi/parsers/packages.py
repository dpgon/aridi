"""Area "packages": installed packages from dpkg, apk, pacman and rpm (TODO.md 3.3).

The databases are read directly when they exist, so Fedora and Alpine are no longer left
without packages (docs/MVP.md n.º 14). Versions are those of the binary package.
"""

from aridi.interpret import AreaResult, register
from aridi.model import Gap, Status

MANAGERS = ("dpkg", "apk", "pacman", "rpm")


def _stanzas(content):
    """Blank-line separated blocks of "Key: value" (dpkg) or "K:value" (apk) lines."""
    block = []
    for line in content.splitlines():
        if line.strip():
            block.append(line)
        elif block:
            yield block
            block = []
    if block:
        yield block


def parse_dpkg(content):
    packages = []
    for block in _stanzas(content):
        fields = {}
        for line in block:
            key, _, value = line.partition(":")
            fields[key.strip()] = value.strip()
        # Only "install ok installed": not removed-but-configured nor half-installed.
        if fields.get("Status") != "install ok installed" or not fields.get("Package"):
            continue
        packages.append({"name": fields["Package"], "version": fields.get("Version"),
                         "arch": fields.get("Architecture")})
    return packages


def parse_apk(content):
    packages = []
    for block in _stanzas(content):
        fields = {line[0]: line[2:] for line in block if len(line) > 1 and line[1] == ":"}
        if fields.get("P"):
            packages.append({"name": fields["P"], "version": fields.get("V"),
                             "arch": fields.get("A")})
    return packages


def parse_pacman(content):
    packages = []
    for block in _stanzas(content):
        fields = {}
        for line in block:
            key, _, value = line.partition(" ")
            fields[key] = value
        if fields.get("%NAME%"):
            packages.append({"name": fields["%NAME%"], "version": fields.get("%VERSION%"),
                             "arch": fields.get("%ARCH%")})
    return packages


def parse_rpm(content):
    """(packages, gpg_pubkeys) from NAME EPOCH VERSION RELEASE ARCH, tab separated."""
    packages, keys = [], 0
    for line in content.splitlines():
        fields = line.split("\t")
        if len(fields) != 5 or not fields[0]:
            continue
        name, epoch, version, release, arch = fields
        if name == "gpg-pubkey":
            keys += 1
            continue
        full = f"{version}-{release}"
        if epoch not in ("(none)", ""):
            full = f"{epoch}:{full}"
        packages.append({"name": name, "version": full,
                         "arch": None if arch == "(none)" else arch})
    return packages, keys


@register("packages")
def parse(sections):
    packages, gaps, managers = [], [], {}
    gpg_pubkeys = 0
    for manager in MANAGERS:
        raw = sections.get(f"packages.{manager}")
        if raw is None or raw.status == "na":
            continue
        if raw.status != "ok":
            gaps.append(Gap(manager, Status(raw.status),
                            f"packages.{manager} {raw.status}" +
                            (f": {raw.note}" if raw.note else "")))
            continue
        content = raw.text()
        if manager == "rpm":
            found, gpg_pubkeys = parse_rpm(content)
        else:
            found = {"dpkg": parse_dpkg, "apk": parse_apk, "pacman": parse_pacman}[manager](
                content)
        if raw.truncated:
            gaps.append(Gap(manager, Status.ERROR,
                            f"packages.{manager} cut at {raw.limit} bytes: list incomplete"))
        for package in found:
            package["manager"] = manager
        packages.extend(found)
        managers[manager] = len(found)
    if not managers and not gaps:
        gaps.append(Gap("package manager", Status.NA, "no dpkg, apk, pacman nor rpm database"))
    packages.sort(key=lambda p: (p["manager"], p["name"], p["version"] or ""))
    return AreaResult({"managers": managers, "count": len(packages),
                       "gpg_pubkeys": gpg_pubkeys, "packages": packages}, gaps=gaps)
