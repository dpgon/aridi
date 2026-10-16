"""Area "users": accounts, groups and password state (TODO.md 3.7).

The collector sends password fields reduced to their prefix ("$y$", "!$6$", "*", ""):
the hash never leaves the machine. A prefix this core does not know is reported as
"unknown", never fitted into another algorithm (in 2019 yescrypt came out as "no
password", docs/MVP.md n.º 12).
"""

from aridi.interpret import AreaResult, register
from aridi.model import Gap, Status
from aridi.parsers._common import gap, text

ALGORITHMS = {
    "$1$": "md5", "$2a$": "bcrypt", "$2b$": "bcrypt", "$2y$": "bcrypt", "$2x$": "bcrypt",
    "$5$": "sha256", "$6$": "sha512", "$7$": "scrypt", "$y$": "yescrypt",
    "$gy$": "gost-yescrypt", "$sha1$": "sha1", "$md5$": "sun-md5",
    "des": "des", "bsdi": "bsdi-des",
}


def password_state(prefix):
    """(state, algorithm) of a filtered password field.

    state: "set", "locked" (! or * marks, with or without a hash behind), "empty" (no
    password: anyone can log in where it is allowed), "invalid" (a text that is not a
    hash, e.g. "locked": no password can match it) or "unknown".
    """
    if prefix is None:
        return "unknown", None
    stripped = prefix.lstrip("!")
    locked = stripped != prefix or stripped == "*"
    if stripped.startswith("$"):
        algorithm = ALGORITHMS.get(stripped, "unknown")
        return ("locked" if locked else "set"), algorithm
    if stripped == "*":
        return "locked", None
    if stripped == "":
        return ("locked" if locked else "empty"), None
    if stripped in ALGORITHMS:                 # des, bsdi: traditional crypt
        return ("locked" if locked else "set"), ALGORITHMS[stripped]
    if stripped == "other":
        return ("locked" if locked else "invalid"), None
    return ("locked" if locked else "set"), "unknown"


def _rows(content, minimum):
    for line in content.splitlines():
        fields = line.split(":")
        if len(fields) >= minimum and fields[0]:
            yield fields


def _int(value):
    return int(value) if value.isdigit() else None


@register("users")
def parse(sections):
    gaps = []
    passwd = text(sections, "users.passwd")
    if passwd is None:
        gaps.append(gap(sections, "accounts", ["users.passwd"], "no /etc/passwd"))
    group = text(sections, "users.group")
    if group is None:
        gaps.append(gap(sections, "groups", ["users.group"], "no /etc/group"))

    shadow = {}
    shadow_text = text(sections, "users.shadow")
    if shadow_text is None:
        gaps.append(gap(sections, "password state", ["users.shadow"], "no /etc/shadow"))
    else:
        for fields in _rows(shadow_text, 2):
            fields += [""] * (9 - len(fields))
            shadow[fields[0]] = {"prefix": fields[1], "last_change": _int(fields[2]),
                                 "min_days": _int(fields[3]), "max_days": _int(fields[4]),
                                 "warn_days": _int(fields[5]), "inactive_days": _int(fields[6]),
                                 "expire": _int(fields[7])}

    users, by_name = [], {}
    for fields in _rows(passwd or "", 7):
        name, field, uid, gid, gecos, home, shell = fields[:7]
        if field == "x":
            prefix = shadow.get(name, {}).get("prefix")    # None: shadow not readable
        else:
            prefix = field        # password in /etc/passwd itself, also filtered at source
        state, algorithm = password_state(prefix)
        user = {"name": name, "uid": _int(uid), "gid": _int(gid), "gecos": gecos,
                "home": home, "shell": shell, "groups": [], "password": state,
                "algorithm": algorithm,
                "aging": {k: v for k, v in shadow.get(name, {}).items() if k != "prefix"}}
        users.append(user)
        by_name[name] = user

    groups, orphans = [], []
    gid_names = {}
    for fields in _rows(group or "", 4):
        name, _, gid, members = fields[:4]
        member_list = [m for m in members.split(",") if m]
        groups.append({"name": name, "gid": _int(gid), "members": member_list})
        gid_names[_int(gid)] = name
        for member in member_list:
            if member in by_name:
                by_name[member]["groups"].append(name)
            else:
                # A member without local account (LDAP, removed user...): recorded, never
                # an error (it broke gathering2.py:112 in 2019).
                orphans.append({"group": name, "member": member})
    for user in users:
        primary = gid_names.get(user["gid"])
        if primary and primary not in user["groups"]:
            user["groups"].insert(0, primary)
        if user["gid"] is not None and primary is None:
            user["primary_group_missing"] = True

    algorithms = {}
    for user in users:
        if user["password"] in ("set", "locked") and user["algorithm"]:
            algorithms[user["algorithm"]] = algorithms.get(user["algorithm"], 0) + 1
    states = {}
    for user in users:
        states[user["password"]] = states.get(user["password"], 0) + 1
    # Only where it matters: an active password whose algorithm is not known.
    unknown = [u["name"] for u in users if u["algorithm"] == "unknown" and u["password"] == "set"]
    if unknown:
        gaps.append(Gap("password algorithm", Status.ERROR,
                        f"unknown hash prefix for: {', '.join(unknown)}"))
    data = {"users": users, "groups": groups, "members_without_account": orphans,
            "password_states": states, "algorithms": algorithms,
            "shadow_read": shadow_text is not None}
    return AreaResult(data, gaps=gaps)
