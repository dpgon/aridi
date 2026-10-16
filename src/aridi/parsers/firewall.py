"""Area "firewall": nftables, iptables, firewalld and ufw (TODO.md 3.10).

Accept rules are summarized per direction (input, output, forward) with source,
destination, protocol and port. A single address (/32, /128 or no prefix) in an accept rule
becomes a relation fw_allowed_in or fw_allowed_out.
"""

import ipaddress
import json
import re

from aridi.interpret import AreaResult, register
from aridi.model import Gap, Relation, Role, Status
from aridi.parsers._common import text

DIRECTIONS = {"input": "input", "output": "output", "forward": "forward",
              "INPUT": "input", "OUTPUT": "output", "FORWARD": "forward"}


def _value(right):
    """Text of the right side of an nft JSON match: address, prefix, port, set..."""
    if isinstance(right, dict):
        if "prefix" in right:
            return f"{right['prefix'].get('addr')}/{right['prefix'].get('len')}"
        if "set" in right:
            return ",".join(_value(item) for item in right["set"])
        if "range" in right:
            return "-".join(str(_value(item)) for item in right["range"])
        return json.dumps(right, sort_keys=True)
    return str(right)


def parse_nft_json(content):
    """(chains, rules) from "nft -j list ruleset"."""
    chains, rules = [], []
    hooks = {}
    for item in json.loads(content).get("nftables", []):
        if "chain" in item:
            chain = item["chain"]
            key = (chain.get("family"), chain.get("table"), chain.get("name"))
            hooks[key] = chain.get("hook")
            chains.append({"family": chain.get("family"), "table": chain.get("table"),
                           "name": chain.get("name"), "hook": chain.get("hook"),
                           "policy": chain.get("policy")})
        elif "rule" in item:
            rule = item["rule"]
            exprs = rule.get("expr", [])
            verdict = next((key for expr in exprs for key in expr
                            if key in ("accept", "drop", "reject", "jump", "goto", "return")),
                           None)
            parsed = {"engine": "nftables", "family": rule.get("family"),
                      "table": rule.get("table"), "chain": rule.get("chain"),
                      "direction": DIRECTIONS.get(hooks.get(
                          (rule.get("family"), rule.get("table"), rule.get("chain")))),
                      "action": verdict, "source": None, "destination": None,
                      "protocol": None, "port": None}
            for expr in exprs:
                match = expr.get("match")
                if not match or match.get("op") not in ("==", "in"):
                    continue
                payload = (match.get("left") or {}).get("payload") or {}
                field, value = payload.get("field"), _value(match.get("right"))
                if field == "saddr":
                    parsed["source"] = value
                elif field == "daddr":
                    parsed["destination"] = value
                elif field == "dport":
                    parsed["protocol"] = payload.get("protocol")
                    parsed["port"] = value
            rules.append(parsed)
    return chains, rules


_IPT_OPTION = re.compile(r"(?:^|\s)(-s|-d|-p|--dport|--dports|-j)\s+(\S+)")


def parse_iptables_save(content, family):
    """(chains, rules) from iptables-save / ip6tables-save."""
    chains, rules, table = [], [], None
    for line in content.splitlines():
        if line.startswith("*"):
            table = line[1:].strip()
        elif line.startswith(":"):
            name, policy = (line[1:].split() + ["", ""])[:2]
            chains.append({"family": family, "table": table, "name": name,
                           "hook": DIRECTIONS.get(name), "policy": None if policy == "-"
                           else policy.lower()})
        elif line.startswith("-A "):
            chain = line.split()[1]
            options = {key: value for key, value in _IPT_OPTION.findall(line)}
            target = options.get("-j", "")
            rules.append({"engine": "iptables", "family": family, "table": table,
                          "chain": chain, "direction": DIRECTIONS.get(chain),
                          "action": target.lower() if target else None,
                          "source": options.get("-s"), "destination": options.get("-d"),
                          "protocol": options.get("-p"),
                          "port": options.get("--dport") or options.get("--dports")})
    return chains, rules


def parse_firewalld(content):
    zones, current = [], None
    for line in content.splitlines():
        if line and not line.startswith((" ", "\t")):
            name = line.split()[0]
            current = {"zone": name, "active": "(active)" in line, "rich_rules": []}
            zones.append(current)
        elif current is not None and ":" in line and not line.startswith("\t"):
            key, _, value = line.strip().partition(":")
            current[key.strip().replace(" ", "_")] = value.split()
        elif current is not None and line.strip():
            current["rich_rules"].append(line.strip())
    return zones


def parse_ufw(content):
    result = {"active": None, "defaults": None, "rules": []}
    for line in content.splitlines():
        if line.startswith("Status:"):
            result["active"] = line.split(":", 1)[1].strip() == "active"
        elif line.startswith("Default:"):
            result["defaults"] = line.split(":", 1)[1].strip()
        elif re.match(r"^\S.*\s{2,}(ALLOW|DENY|REJECT|LIMIT)", line):
            result["rules"].append(re.split(r"\s{2,}", line.strip()))
    return result


def _single_address(value):
    """The IP of VALUE if it is one host (/32, /128 or no prefix), else None."""
    if not value or "," in value or "-" in value:
        return None
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None
    if network.num_addresses == 1:
        return network.network_address
    return None


@register("firewall")
def parse(sections):
    gaps, engines, chains, rules = [], [], [], []
    nft_json = text(sections, "firewall.nft_json")
    if nft_json:
        try:
            found_chains, found_rules = parse_nft_json(nft_json)
        except (ValueError, AttributeError) as exc:
            gaps.append(Gap("nftables", Status.ERROR, f"nft JSON not readable: {exc}"))
        else:
            engines.append("nftables")
            chains += found_chains
            rules += found_rules
    for name, family in (("firewall.iptables_legacy", "ip"),
                         ("firewall.ip6tables_legacy", "ip6")):
        content = text(sections, name)
        if content and content.strip():
            found_chains, found_rules = parse_iptables_save(content, family)
            if "iptables" not in engines:
                engines.append("iptables")
            chains += found_chains
            rules += found_rules
    firewalld = text(sections, "firewall.firewalld")
    zones = parse_firewalld(firewalld) if firewalld else None
    if zones is not None:
        engines.append("firewalld")
    ufw_text = text(sections, "firewall.ufw")
    ufw = parse_ufw(ufw_text) if ufw_text else None
    if ufw is not None:
        engines.append("ufw")

    nft_text = sections.get("firewall.nft")
    raw_json = sections.get("firewall.nft_json")
    if (raw_json is not None and raw_json.status == "missing" and nft_text is not None
            and nft_text.status == "ok"):
        # Old nft without JSON: the ruleset is there but its rules are not analyzed.
        engines.append("nftables")
        gaps.append(Gap("nftables rules", Status.MISSING,
                        "nft has no JSON output (before 0.9): rules not analyzed"))
    for name in ("firewall.nft_json", "firewall.iptables_legacy", "firewall.ip6tables_legacy",
                 "firewall.firewalld", "firewall.ufw"):
        raw = sections.get(name)
        if raw is not None and raw.status in ("denied", "timeout", "error"):
            gaps.append(Gap(name.removeprefix("firewall."), Status(raw.status),
                            raw.note or f"{name} {raw.status}"))

    relations = []
    for rule in rules:
        if rule["action"] != "accept":
            continue
        if rule["direction"] == "input":
            address = _single_address(rule["source"])
            role = Role.FW_ALLOWED_IN
        elif rule["direction"] == "output":
            address = _single_address(rule["destination"])
            role = Role.FW_ALLOWED_OUT
        else:
            continue
        if address is not None:
            port = f" {rule['protocol'] or ''}/{rule['port']}" if rule["port"] else ""
            relations.append(Relation(address, role, "firewall",
                                      f"{rule['engine']} {rule['chain']}{port}".strip()))
    for zone in zones or []:
        for rich in zone["rich_rules"]:
            match = re.search(r'source address="?([0-9a-fA-F.:/]+)"?', rich)
            address = _single_address(match.group(1)) if match else None
            if address is not None and " accept" in rich:
                relations.append(Relation(address, Role.FW_ALLOWED_IN, "firewall",
                                          f"firewalld {zone['zone']}"))

    if not engines and not gaps:
        gaps.append(Gap("firewall", Status.NA, "no firewall engine with rules found"))
    data = {"engines": engines, "chains": chains, "rules": rules, "firewalld_zones": zones,
            "ufw": ufw}
    return AreaResult(data, relations=relations, gaps=gaps)
