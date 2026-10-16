"""Area "hardware": CPU, memory and USB (TODO.md 3.2).

The CPU count comes from /sys topology and /proc/cpuinfo processor entries, never from
x86-only fields: in 2019 an arm64 machine gave "0 cores" and an empty model
(docs/MVP.md n.º 11).
"""

import re

from aridi.interpret import AreaResult, register
from aridi.model import Gap, Status
from aridi.parsers._common import first_line, gap, text

# ARM "CPU implementer" codes (Linux arch/arm64/include/asm/cputype.h).
ARM_IMPLEMENTERS = {
    "0x41": "ARM", "0x42": "Broadcom", "0x43": "Cavium", "0x44": "DEC", "0x46": "Fujitsu",
    "0x48": "HiSilicon", "0x49": "Infineon", "0x4d": "Motorola", "0x4e": "NVIDIA",
    "0x50": "APM", "0x51": "Qualcomm", "0x53": "Samsung", "0x56": "Marvell",
    "0x61": "Apple", "0x66": "Faraday", "0x69": "Intel", "0x6d": "Microsoft",
    "0x70": "Phytium", "0xc0": "Ampere",
}

# A few well-known parts: (implementer, part) -> name. Anything else is reported by code.
ARM_PARTS = {
    ("0x41", "0xd03"): "Cortex-A53", ("0x41", "0xd04"): "Cortex-A35",
    ("0x41", "0xd05"): "Cortex-A55", ("0x41", "0xd07"): "Cortex-A57",
    ("0x41", "0xd08"): "Cortex-A72", ("0x41", "0xd09"): "Cortex-A73",
    ("0x41", "0xd0a"): "Cortex-A75", ("0x41", "0xd0b"): "Cortex-A76",
    ("0x41", "0xd0c"): "Neoverse-N1", ("0x41", "0xd0d"): "Cortex-A77",
    ("0x41", "0xd40"): "Neoverse-V1", ("0x41", "0xd41"): "Cortex-A78",
    ("0x41", "0xd49"): "Neoverse-N2", ("0x41", "0xd4f"): "Neoverse-V2",
    ("0xc0", "0xac3"): "Ampere-1", ("0x61", "0x022"): "Apple M1 Icestorm",
    ("0x61", "0x023"): "Apple M1 Firestorm",
}

_KB = re.compile(r"(\d+)\s*kB")


def cpuinfo_blocks(content):
    """List of {key: value} per blank-line separated block of /proc/cpuinfo."""
    blocks, current = [], {}
    for line in content.splitlines():
        if not line.strip():
            if current:
                blocks.append(current)
                current = {}
            continue
        key, sep, value = line.partition(":")
        if sep:
            current[key.strip().lower()] = value.strip()
    if current:
        blocks.append(current)
    return blocks


def cpu_list(value):
    """Set of CPU numbers from a kernel list like "0-3,8,10-11"."""
    cpus = set()
    for part in (value or "").strip().split(","):
        if not part:
            continue
        first, _, last = part.partition("-")
        if not first.isdigit() or (last and not last.isdigit()):
            raise ValueError(f"invalid CPU list {value!r}")
        cpus.update(range(int(first), int(last or first) + 1))
    return cpus


def _topology(content):
    cpus = {}
    for line in (content or "").splitlines():
        name, *fields = line.split()
        if not name.startswith("cpu"):
            continue
        values = dict(field.partition("=")[::2] for field in fields)
        cpus[name] = values
    return cpus


def _model(blocks):
    """(vendor, model, source) from the first processor block of /proc/cpuinfo."""
    info = next((b for b in blocks if "model name" in b or "cpu implementer" in b), None)
    if info is None:
        info = blocks[0] if blocks else {}
    if "vendor_id" in info or "model name" in info:
        return info.get("vendor_id"), info.get("model name"), "cpuinfo"
    implementer = info.get("cpu implementer", "").lower()
    if implementer:
        part = info.get("cpu part", "").lower()
        vendor = ARM_IMPLEMENTERS.get(implementer, f"implementer {implementer}")
        model = ARM_PARTS.get((implementer, part)) or f"{vendor} part {part or '?'}"
        return vendor, model, "cpuinfo-arm"
    return None, None, None


def _memory(content):
    values = {}
    for line in (content or "").splitlines():
        key, _, rest = line.partition(":")
        match = _KB.fullmatch(rest.strip())
        if match:
            values[key.strip()] = int(match.group(1)) * 1024
    return values


def _usb(content):
    devices, current = [], None
    for line in (content or "").splitlines():
        if line.startswith("device "):
            current = {"device": line[7:].strip()}
            devices.append(current)
        elif current is not None and "=" in line:
            key, _, value = line.partition("=")
            current[key] = value
    for dev in devices:
        vendor = dev.get("idVendor", "").lower()
        dev["hub"] = dev.get("bDeviceClass") == "09"
        dev["root_hub"] = dev["hub"] and vendor == "1d6b"
    return devices


@register("hardware")
def parse(sections):
    gaps = []
    cpuinfo = text(sections, "hardware.cpuinfo")
    blocks = cpuinfo_blocks(cpuinfo) if cpuinfo else []
    processors = [b for b in blocks if "processor" in b]
    if not cpuinfo:
        gaps.append(gap(sections, "cpuinfo", ["hardware.cpuinfo"], "no /proc/cpuinfo"))

    online = None
    online_text = first_line(text(sections, "hardware.cpu_online"))
    if online_text:
        try:
            online = sorted(cpu_list(online_text))
        except ValueError as exc:
            gaps.append(Gap("online cpus", Status.ERROR, str(exc)))

    topology = _topology(text(sections, "hardware.cpu_topology"))
    # -1 means "unknown" (arm64 without firmware topology); it is not a package.
    packages = {v["package"] for v in topology.values() if v.get("package", "").isdigit()}
    cores = {(v.get("package"), v.get("die"), v.get("cluster"), v.get("core"))
             for v in topology.values() if v.get("core", "").isdigit()}

    logical = len(online) if online else (len(topology) or len(processors) or None)
    vendor, model, model_source = _model(blocks)
    first = processors[0] if processors else {}
    cpu = {
        "architecture": first_line(text(sections, "hardware.machine")),
        "logical": logical,
        "online": online,
        "sockets": len(packages) or None,
        "cores": len(cores) or None,
        "threads_per_core": (logical // len(cores)) if logical and cores else None,
        "vendor": vendor,
        "model": model,
        "model_source": model_source,
        "implementer": first.get("cpu implementer"),
        "part": first.get("cpu part"),
        "flags": (first.get("flags") or first.get("features") or "").split(),
        "bugs": (first.get("bugs") or "").split(),
    }
    if not logical:
        gaps.append(gap(sections, "cpu count", ["hardware.cpu_online", "hardware.cpu_topology"],
                        "neither /sys nor /proc/cpuinfo gave the CPUs"))
    if not cpu["cores"]:
        gaps.append(gap(sections, "cpu topology", ["hardware.cpu_topology"],
                        "no core ids in /sys/devices/system/cpu/*/topology"))
    if not model and cpuinfo:
        gaps.append(Gap("cpu model", Status.ERROR, "no model name nor CPU implementer"))

    meminfo = _memory(text(sections, "hardware.meminfo"))
    memory = {"total": meminfo.get("MemTotal"), "swap_total": meminfo.get("SwapTotal")}
    if memory["total"] is None:
        gaps.append(gap(sections, "memory", ["hardware.meminfo"], "no MemTotal in /proc/meminfo"))

    usb_raw = sections.get("hardware.usb")
    usb = None
    if usb_raw is not None and usb_raw.status == "ok":
        usb = _usb(usb_raw.text())
    elif usb_raw is not None and usb_raw.status != "na":
        gaps.append(gap(sections, "usb", ["hardware.usb"], "USB devices not readable"))
    elif usb_raw is not None:
        gaps.append(Gap("usb", Status.NA, usb_raw.note or "no /sys/bus/usb"))

    return AreaResult({"cpu": cpu, "memory": memory, "usb": usb}, gaps=gaps)
