"""Area "identity": hostname, domain, hostid and banners (TODO.md 3.6).

The domain is the DNS domain of the host, never its hostname (2019 gathering2.py:35
printed the hostname as domain). Banners are untrusted text: kept as received, the views
neutralize them.
"""

from aridi.interpret import AreaResult, register
from aridi.model import Gap, Status
from aridi.parsers._common import first_line, gap, text

BANNERS = (("identity.issue", "/etc/issue"), ("identity.issue_net", "/etc/issue.net"),
           ("identity.motd", "/etc/motd"))


def parse_motd_d(content):
    """{path: text} from the "==> FILE <==" blocks of identity.motd_d."""
    files, current = {}, None
    for line in content.splitlines(keepends=True):
        if line.startswith("==> ") and line.rstrip("\n").endswith(" <=="):
            current = line[4:].rstrip("\n")[:-4]
            files[current] = ""
        elif current is not None:
            files[current] += line
    return {path: body.removesuffix("\n") for path, body in files.items()}


def _domain(sections):
    """(dns domain or "" when there is none, gap or None)."""
    raw = sections.get("identity.dnsdomainname")
    if raw is None or raw.status != "ok":
        return None, gap(sections, "dns domain", ["identity.dnsdomainname"],
                         "dnsdomainname not run")
    value = first_line(raw.text())
    if raw.rc == 0:
        return value or "", None
    # Exit code 1: the hostname does not resolve (no DNS, not in /etc/hosts), so the host
    # has no fully qualified name it can know. Not a failure of aridi, and not "".
    return None, Gap("dns domain", Status.NA,
                     f"the hostname does not resolve: {raw.note or raw.rc}")


@register("identity")
def parse(sections):
    gaps = []
    hostname = (first_line(text(sections, "identity.kernel_hostname"))
                or first_line(text(sections, "identity.hostname")))
    if not hostname:
        gaps.append(gap(sections, "hostname", ["identity.kernel_hostname", "identity.hostname"],
                        "no hostname"))
    domain, domain_gap = _domain(sections)
    if domain_gap:
        gaps.append(domain_gap)
    nis = first_line(text(sections, "identity.nis_domainname"))
    hostid = first_line(text(sections, "identity.hostid"))
    if not hostid:
        gaps.append(gap(sections, "hostid", ["identity.hostid"], "no hostid output"))

    banners = {}
    for name, path in BANNERS:
        raw = sections.get(name)
        if raw is None or raw.status == "na":
            continue
        if raw.status != "ok":
            gaps.append(gap(sections, f"banner {path}", [name], f"{path} not read"))
            continue
        banners[path] = {"text": raw.text(), "truncated": raw.truncated}
    motd_d = text(sections, "identity.motd_d")
    for path, body in parse_motd_d(motd_d).items() if motd_d else ():
        banners[path] = {"text": body, "truncated": False}

    data = {
        "hostname": hostname,
        "etc_hostname": first_line(text(sections, "identity.etc_hostname")),
        "dns_domain": domain,
        "nis_domain": None if nis in (None, "(none)") else nis,
        "hostid": hostid,
        "banners": banners,
    }
    return AreaResult(data, gaps=gaps)
