"""Area "system": distribution, kernel and libc (TODO.md 3.1)."""

import re
import shlex

from aridi.interpret import AreaResult, register
from aridi.parsers._common import first_line, gap, text

OS_RELEASE_KEYS = ("id", "id_like", "name", "version", "version_id", "version_codename",
                   "pretty_name", "build_id", "variant_id")

# Release files used when there is no os-release, in order: (section, id, name).
RELEASE_FILES = (
    ("system.centos_release", "centos", None),
    ("system.fedora_release", "fedora", None),
    ("system.redhat_release", "rhel", None),
    ("system.suse_release", "suse", None),
    ("system.alpine_release", "alpine", "Alpine Linux"),
    ("system.slackware_version", "slackware", None),
    ("system.lsb_release", None, None),
    ("system.debian_version", "debian", "Debian GNU/Linux"),
)

_RELEASE_LINE = re.compile(r"(?P<name>.+?) release (?P<version_id>\S+)(?: \((?P<code>[^)]*)\))?")
_GLIBC = re.compile(r"glibc (\d+\.\d+(?:\.\d+)?)")
_LDD_GLIBC = re.compile(r"^ldd \(.*(?:GNU libc|GLIBC).*\) (\d+\.\d+(?:\.\d+)?)\s*$", re.M)
_MUSL_VERSION = re.compile(r"^Version (\S+)", re.M)


def parse_os_release(content):
    """Dict of the os-release KEY=VALUE pairs, keys in lowercase (freedesktop syntax)."""
    values = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        try:
            words = shlex.split(value, comments=False, posix=True)
            value = " ".join(words)
        except ValueError:
            value = value.strip().strip("\"'")
        values[key.strip().lower()] = value
    return values


def _distribution_from_os_release(values, source):
    dist = {key: values.get(key) for key in OS_RELEASE_KEYS}
    dist["id_like"] = values["id_like"].split() if values.get("id_like") else []
    dist["source"] = source
    return dist


def _distribution_from_release_file(sections):
    for name, dist_id, default_name in RELEASE_FILES:
        content = text(sections, name)
        line = first_line(content)
        if not line:
            continue
        dist = {key: None for key in OS_RELEASE_KEYS}
        dist.update(id=dist_id, id_like=[], pretty_name=line, source=name)
        if name == "system.lsb_release":
            values = parse_os_release(content)
            if not values.get("distrib_id"):
                continue
            dist.update(id=values["distrib_id"].lower(), name=values["distrib_id"],
                        version_id=values.get("distrib_release"),
                        version_codename=values.get("distrib_codename"),
                        pretty_name=values.get("distrib_description") or line)
        elif default_name:
            dist.update(name=default_name, version_id=line, version=line)
        elif name == "system.slackware_version":
            dist_name, _, version = line.partition(" ")
            dist.update(name=dist_name, version_id=version or None, version=version or None)
        else:
            match = _RELEASE_LINE.fullmatch(line)
            if match:
                code = match.group("code")
                dist.update(name=match.group("name"), version_id=match.group("version_id"),
                            version=match.group("version_id") + (f" ({code})" if code else ""))
            else:
                dist.update(name=line)
        return dist
    return None


def _libc(sections):
    """(libc dict or None, reason when unknown)."""
    getconf = first_line(text(sections, "system.getconf_libc"))
    if getconf:
        match = _GLIBC.fullmatch(getconf)
        if match:
            return {"family": "glibc", "version": match.group(1), "source": "getconf"}, None
    ldd = text(sections, "system.ldd_version") or ""
    match = _LDD_GLIBC.search(ldd)
    if match:
        return {"family": "glibc", "version": match.group(1), "source": "ldd"}, None
    if ldd.lstrip().startswith("musl libc"):
        match = _MUSL_VERSION.search(ldd)
        return {"family": "musl", "version": match.group(1) if match else None,
                "source": "ldd"}, None
    loader = first_line(text(sections, "system.musl_loader"))
    if loader:
        return {"family": "musl", "version": None, "source": "loader"}, None
    return None, "neither getconf, ldd nor a musl loader identified the libc"


def _kernel(sections):
    kernel = {
        "ostype": first_line(text(sections, "system.kernel_ostype")),
        "release": first_line(text(sections, "system.kernel_osrelease")),
        "version": first_line(text(sections, "system.kernel_version")),
        "machine": first_line(text(sections, "system.machine")),
        "proc_version": first_line(text(sections, "system.proc_version")),
    }
    if not kernel["release"] and kernel["proc_version"]:
        match = re.match(r"(\S+) version (\S+)", kernel["proc_version"])
        if match:
            kernel["ostype"] = kernel["ostype"] or match.group(1)
            kernel["release"] = match.group(2)
    return kernel


@register("system")
def parse(sections):
    gaps = []
    distribution = None
    for name in ("system.os_release", "system.os_release_usr"):
        content = text(sections, name)
        if content and content.strip():
            distribution = _distribution_from_os_release(parse_os_release(content), name)
            break
    if distribution is None:
        distribution = _distribution_from_release_file(sections)
    if distribution is None:
        gaps.append(gap(sections, "distribution",
                        ["system.os_release", "system.os_release_usr"],
                        "no os-release nor release file"))

    release_files = {}
    for name, _, _ in RELEASE_FILES:
        line = first_line(text(sections, name))
        if line and name != "system.lsb_release":
            release_files[name.removeprefix("system.")] = line

    kernel = _kernel(sections)
    if not kernel["release"]:
        gaps.append(gap(sections, "kernel", ["system.kernel_osrelease", "system.proc_version"],
                        "no kernel release in /proc"))
    if not kernel["machine"]:
        gaps.append(gap(sections, "architecture", ["system.machine"], "no uname -m"))

    libc, reason = _libc(sections)
    if libc is None:
        gaps.append(gap(sections, "libc", ["system.ldd_version", "system.getconf_libc"],
                        reason))
    elif libc["version"] is None:
        gaps.append(gap(sections, "libc version", ["system.ldd_version"], reason or
                        "the libc was identified by its loader only"))

    data = {"distribution": distribution, "release_files": release_files, "kernel": kernel,
            "libc": libc}
    return AreaResult(data, gaps=gaps)
