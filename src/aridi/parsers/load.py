"""Area "load" (volatile): memory, load average, CPU and disk usage (TODO.md 3.13).

The disk busy percentage is the time doing I/O over the interval: ms / (seconds * 1000)
* 100. The 2019 code divided by 1000 twice (docs/MVP.md n.º 13).
"""

from aridi.interpret import AreaResult, register
from aridi.parsers._common import first_line, gap, text

CPU_FIELDS = ("user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal")
SECTOR = 512


def parse_meminfo(content):
    values = {}
    for line in content.splitlines():
        key, _, rest = line.partition(":")
        fields = rest.split()
        if fields and fields[0].isdigit():
            values[key.strip()] = int(fields[0]) * (1024 if fields[1:] == ["kB"] else 1)
    return values


def memory(values):
    total, free = values.get("MemTotal"), values.get("MemFree")
    if total is None or free is None:
        return None
    buffers = values.get("Buffers", 0)
    cache = values.get("Cached", 0) + values.get("SReclaimable", 0)
    return {"total": total, "free": free, "available": values.get("MemAvailable"),
            "buffers": buffers, "cache": cache, "used": total - free - buffers - cache,
            "swap_total": values.get("SwapTotal"), "swap_free": values.get("SwapFree"),
            "swap_used": (values["SwapTotal"] - values["SwapFree"])
            if "SwapTotal" in values and "SwapFree" in values else None}


def cpu_times(content):
    for line in content.splitlines():
        fields = line.split()
        if fields and fields[0] == "cpu":
            return dict(zip(CPU_FIELDS, (int(v) for v in fields[1:9])))
    return None


def cpu_percent(times):
    total = sum(times.values())
    if not total:
        return None
    return {key: round(100 * value / total, 2) for key, value in times.items()}


def parse_diskstats(content):
    disks = {}
    for line in content.splitlines():
        fields = line.split()
        if len(fields) >= 14 and fields[3].isdigit():
            disks[fields[2]] = {"reads": int(fields[3]), "read_sectors": int(fields[5]),
                                "writes": int(fields[7]), "write_sectors": int(fields[9]),
                                "io_ms": int(fields[12])}
    return disks


def disk_usage(first, second, seconds):
    usage = []
    for name, after in second.items():
        before = first.get(name)
        if before is None or name.startswith(("loop", "ram", "nbd")):
            continue
        delta = {key: after[key] - before[key] for key in after}
        usage.append({
            "device": name,
            "busy_percent": round(min(100.0, delta["io_ms"] / (seconds * 1000) * 100), 2),
            "reads_per_second": round(delta["reads"] / seconds, 2),
            "writes_per_second": round(delta["writes"] / seconds, 2),
            "read_bytes_per_second": round(delta["read_sectors"] * SECTOR / seconds),
            "write_bytes_per_second": round(delta["write_sectors"] * SECTOR / seconds),
        })
    return sorted(usage, key=lambda d: d["device"])


def _uptime(sections, name):
    value = first_line(text(sections, name))
    return float(value.split()[0]) if value else None


@register("load")
def parse(sections):
    gaps = []
    meminfo = text(sections, "load.meminfo")
    mem = memory(parse_meminfo(meminfo)) if meminfo else None
    if mem is None:
        gaps.append(gap(sections, "memory", ["load.meminfo"], "no /proc/meminfo"))

    loadavg = first_line(text(sections, "load.loadavg"))
    load = None
    if loadavg:
        fields = loadavg.split()
        running, _, total = fields[3].partition("/") if len(fields) > 3 else ("", "", "")
        load = {"1": float(fields[0]), "5": float(fields[1]), "15": float(fields[2]),
                "running": int(running) if running.isdigit() else None,
                "tasks": int(total) if total.isdigit() else None}
    else:
        gaps.append(gap(sections, "load average", ["load.loadavg"], "no /proc/loadavg"))

    stat_1, stat_2 = text(sections, "load.stat_1"), text(sections, "load.stat_2")
    times_1 = cpu_times(stat_1) if stat_1 else None
    times_2 = cpu_times(stat_2) if stat_2 else None
    cpu = {"since_boot": cpu_percent(times_2) if times_2 else None, "last_second": None}
    if times_1 and times_2:
        cpu["last_second"] = cpu_percent({k: times_2[k] - times_1[k] for k in times_2})
    if times_2 is None:
        gaps.append(gap(sections, "cpu", ["load.stat_2"], "no /proc/stat"))

    seconds = None
    up_1, up_2 = _uptime(sections, "load.uptime_1"), _uptime(sections, "load.uptime_2")
    if up_1 is not None and up_2 is not None and up_2 > up_1:
        seconds = up_2 - up_1
    disks_1, disks_2 = text(sections, "load.diskstats_1"), text(sections, "load.diskstats_2")
    disks = None
    if disks_1 and disks_2 and seconds:
        disks = disk_usage(parse_diskstats(disks_1), parse_diskstats(disks_2), seconds)
    else:
        gaps.append(gap(sections, "disk usage", ["load.diskstats_2", "load.uptime_2"],
                        "two samples of /proc/diskstats and /proc/uptime are needed"))

    files = None
    file_nr = first_line(text(sections, "load.file_nr"))
    if file_nr and len(file_nr.split()) == 3:
        allocated, unused, maximum = (int(v) for v in file_nr.split())
        files = {"allocated": allocated, "unused": unused, "max": maximum}
    inodes = None
    inode_nr = first_line(text(sections, "load.inode_nr"))
    if inode_nr and len(inode_nr.split()) >= 2:
        count, free = (int(v) for v in inode_nr.split()[:2])
        inodes = {"count": count, "free": free}

    data = {"memory": mem, "load": load, "cpu": cpu, "interval_seconds": seconds,
            "disks": disks, "files": files, "inodes": inodes}
    return AreaResult(data, gaps=gaps)
