"""Area "processes" (volatile): every process with state, user, memory and CPU
(TODO.md 3.12).

Works with any number of processes (in 2019 fewer than 10 broke the top 10, docs/MVP.md
n.º 17) and with uids that have no account (n.º 16): the uid is shown instead.
"""

from aridi.interpret import AreaResult, register
from aridi.model import Gap, Status
from aridi.parsers._common import first_line, gap, text, user_names

# USER_HZ is 100 on every Linux architecture aridi targets (it differs only on alpha and
# ia64); used when getconf is missing, and declared as such.
DEFAULT_CLK_TCK = 100
TOP = 10


def parse_stat(line):
    """Fields of one /proc/PID/stat line; the command may contain spaces and ")"."""
    left, sep, right = line.rpartition(")")
    if not sep:
        return None
    pid, _, comm = left.partition(" (")
    fields = right.split()
    if not pid.strip().isdigit() or len(fields) < 20:
        return None
    return {"pid": int(pid), "comm": comm, "state": fields[0], "ppid": int(fields[1]),
            "utime": int(fields[11]), "stime": int(fields[12]), "nice": int(fields[16]),
            "starttime": int(fields[19])}


def cpu_percent(proc, uptime, clk_tck):
    """%CPU since the process started (formula of 2019 gathering3.py:66-75)."""
    seconds = uptime - proc["starttime"] / clk_tck
    if seconds <= 0:
        return 0.0
    return round(100 * ((proc["utime"] + proc["stime"]) / clk_tck) / seconds, 2)


@register("processes", uses=("users",))
def parse(sections):
    gaps = []
    stat = text(sections, "processes.stat")
    if stat is None:
        gap_ = gap(sections, "processes", ["processes.stat"], "no /proc/PID/stat")
        return AreaResult(None, status=gap_.status, reason=gap_.reason)

    status = {}
    for line in (text(sections, "processes.status") or "").splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[0].isdigit():
            status[int(fields[0])] = {
                "uid": int(fields[1]) if fields[1].isdigit() else None,
                "rss": int(fields[2]) * 1024 if len(fields) > 2 and fields[2].isdigit() else None,
                "threads": int(fields[3]) if len(fields) > 3 and fields[3].isdigit() else None}
    cmdlines = {}
    for line in (text(sections, "processes.cmdline") or "").splitlines():
        pid, _, cmdline = line.partition(" ")
        if pid.isdigit():
            cmdlines[int(pid)] = cmdline.strip()

    uptime_text = first_line(text(sections, "processes.uptime"))
    uptime = float(uptime_text.split()[0]) if uptime_text else None
    clk_text = first_line(text(sections, "processes.clk_tck"))
    clk_tck, clk_source = ((int(clk_text), "getconf") if clk_text and clk_text.isdigit()
                           else (DEFAULT_CLK_TCK, "default"))
    if uptime is None:
        gaps.append(gap(sections, "cpu percent", ["processes.uptime"], "no /proc/uptime"))
    names = user_names(sections)

    processes = []
    for line in stat.splitlines():
        proc = parse_stat(line)
        if proc is None:
            continue
        info = status.get(proc["pid"], {})
        uid = info.get("uid")
        processes.append({
            "pid": proc["pid"], "ppid": proc["ppid"], "comm": proc["comm"],
            "state": proc["state"], "nice": proc["nice"], "uid": uid,
            # A uid without account shows as the number itself.
            "user": names.get(uid, str(uid) if uid is not None else None),
            "rss": info.get("rss"), "threads": info.get("threads"),
            "cpu": cpu_percent(proc, uptime, clk_tck) if uptime is not None else None,
            "cmdline": cmdlines.get(proc["pid"]),
        })
    processes.sort(key=lambda p: p["pid"])
    if not processes:
        gaps.append(Gap("processes", Status.ERROR, "no process could be read"))

    by_state = {}
    for proc in processes:
        by_state[proc["state"]] = by_state.get(proc["state"], 0) + 1
    data = {
        "count": len(processes), "by_state": by_state,
        "zombies": [p["pid"] for p in processes if p["state"] == "Z"],
        "clk_tck": clk_tck, "clk_tck_source": clk_source,
        "top_memory": [p["pid"] for p in sorted(
            processes, key=lambda p: -(p["rss"] or 0))[:TOP]],
        "top_cpu": [p["pid"] for p in sorted(processes, key=lambda p: -(p["cpu"] or 0))[:TOP]],
        "processes": processes,
    }
    return AreaResult(data, gaps=gaps)
