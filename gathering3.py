import traceback, re
from datetime import timedelta, datetime
from time import sleep
from gathering1 import _getdisks
from gathering2 import _getusers, _getnetinfo
from os import walk, listdir, sysconf_names, sysconf, readlink
from utils import detailheader, detailfile, converthex2ipport
from subprocess import check_output, DEVNULL
from ipaddress import ip_address
from locale import setlocale, LC_TIME

# Process information
# pid : [common name, status, effective owner, owner name,
#        memory used, nice, total CPU usage and cli name]
process = {}
uptime = 0

tcpstate = {1: "ESTABLISHED", 2: "SYN SENT", 3: "SYN RECV", 4: "FIN WAIT1",
            5: "FIN WAIT2", 6: "TIME WAIT", 7: "CLOSE", 8: "CLOSE_WAIT",
            9: "LAST ACK", 10: "LISTEN", 11: "CLOSING", 12: "NEW SYN RECV",
            13: "MAX STATES"}


def _getprocessdata(report):
    global uptime
    # User_HZ for process cpu usage
    userhz = int(sysconf(sysconf_names['SC_CLK_TCK']))

    for item in listdir("/proc"):
        if re.findall(r'\d+', item):
            process[int(item)] = ""

    for item in process:
        comm = None
        status = None
        euid = None
        uidname = None
        vmrss = 0
        nice = 0
        cmdline = None
        cpu_usage = 0

        try:
            with open("/proc/{}/cmdline".format(item)) as f:
                cmdline = " ".join(f.read().split("\x00"))

            with open("/proc/{}/comm".format(item)) as f:
                comm = f.read().strip()

            with open("/proc/{}/status".format(item)) as f:
                lines = f.readlines()
                for line in lines:
                    if "State" in line:
                        status = line.split(":")[1].strip()[0]
                    if "Uid" in line:
                        euid = line.split(":")[1].strip().split()[1]
                        uidname = [x for x in report.users
                                   if report.users.get(x, [0, -1])[1] == euid][0]
                    if "VmRSS" in line:
                        vmrss = int(re.findall("\d+", line.split(":")[1].strip())[0])

            with open("/proc/uptime".format(item)) as f:
                uptime = float(f.read().strip().split()[0])

            with open("/proc/{}/stat".format(item)) as f:
                line = f.read().strip().split(")")[1].split()
                if len(line) > 16:
                    nice = int(line[16])
                    utime = int(line[11])
                    stime = int(line[12])
                    starttime = int(line[19])
                    totaltime = utime + stime
                    seconds = uptime - (starttime / userhz)
                    cpu_usage = round(100 * ((totaltime / userhz) / seconds), 2)

            process[item] = [comm, status, euid, uidname, vmrss, nice, cpu_usage, cmdline]

        except Exception as e:
            report.log("DEBUG", "Can't obtain process information of PID {}".format(item))
            report.log("DEBUG", str(e))
            report.log("DEBUG", traceback.format_exc())


def _getprocess():
    summ = "\nProcess information:\n"
    detail = detailheader("Process information")
    detail += detailfile("Process Summary")

    keylist = list(process.keys())
    keylist.sort()

    total = len(keylist)
    running = 0
    runningdata = []
    sleeping = 0
    sleepingdata = []
    idle = 0
    zombie = 0
    zombiedata = []
    topcpu = []
    topmem = []

    for item in keylist:
        try:
            if process[item][6]:
                topcpu.append([process[item][6], item])
            if process[item][4]:
                topmem.append([process[item][4], item])

            if 'R' in process[item][1]:
                running += 1
                runningdata.append([item, process[item]])
            if 'S' in process[item][1]:
                sleeping += 1
                sleepingdata.append([item, process[item]])
            if 'I' in process[item][1]:
                idle += 1
            if 'Z' in process[item][1]:
                zombie += 1
                zombiedata.append([item, process[item]])
        except:
            pass  # Process deleted

    topcpu.sort(reverse=True)
    topmem.sort(reverse=True)

    summ += " |__{} total process, {} running, {} sleeping, " \
            "{} idle and {} zombie\n".format(total, running, sleeping, idle, zombie)
    detail += "Total processes\n"
    detail += " |__{} total process, {} running, {} sleeping, " \
              "{} idle and {} zombie\n".format(total, running, sleeping, idle, zombie)

    summ += " |__Top 5 CPU process:\n"
    detail += " |__Top 10 CPU process:\n"
    for counter in range(10):
        if len(process[topcpu[counter][1]][7]) > 59:
            if counter < 5:
                summ += " |       |__{:_>5}% {}...\n".format(topcpu[counter][0],
                                                             process[topcpu[counter][1]][7][:56])
            detail += " |       |__{:_>5}% {}...\n".format(topcpu[counter][0],
                                                           process[topcpu[counter][1]][7][:56])
        else:
            if counter < 5:
                summ += " |       |__{:_>5}% {}\n".format(topcpu[counter][0],
                                                          process[topcpu[counter][1]][7])
            detail += " |       |__{:_>5}% {}\n".format(topcpu[counter][0],
                                                        process[topcpu[counter][1]][7])

    summ += " |__Top 5 RAM process:\n"
    detail += " |__Top 10 RAM process:\n"
    for counter in range(10):
        if len(process[topmem[counter][1]][7]) > 59:
            if counter < 5:
                summ += "         |__{:_>7} kB {}...\n".format(topmem[counter][0],
                                                               process[topmem[counter][1]][7][:56])
            detail += "         |__{:_>7} kB {}...\n".format(topmem[counter][0],
                                                             process[topmem[counter][1]][7][:56])
        else:
            if counter < 5:
                summ += "         |__{:_>7} kB {}\n".format(topmem[counter][0],
                                                            process[topmem[counter][1]][7])
            detail += "         |__{:_>7} kB {}\n".format(topmem[counter][0],
                                                          process[topmem[counter][1]][7])

    detail += detailfile("Process detail")
    detail += "{:^80}\n".format("(PID, user, niceness, memory in kB, %cpu and name)")

    if running > 0:
        detail += "Running processes\n"
        for item in runningdata:
            detail += " |__{:5} {:12} {:3} {:7} {:5}% {}\n".format(item[0], item[1][3][:12],
                                                                   item[1][5], item[1][4],
                                                                   item[1][6], item[1][7][:35])
    if zombie > 0:
        detail += "\nZombie processes\n"
        for item in zombiedata:
            detail += " |__{:5} {:12} {:3} {:7} {:5}% {}\n".format(item[0], item[1][3][:12],
                                                                   item[1][5], item[1][4],
                                                                   item[1][6], item[1][0][:35])

    if sleeping > 0:
        detail += "\nSleeping processes\n"
        for item in sleepingdata:
            detail += " |__{:5} {:12} {:3} {:7} {:5}% {}\n".format(item[0], item[1][3][:12],
                                                                   item[1][5], item[1][4],
                                                                   item[1][6], item[1][7][:35])

    return summ, detail


def _getuserdata(precheck, report):
    detail = detailheader("Users information")

    summ = "\nUsers:\n"

    if precheck.checkcommand("utmpdump"):
        detail += "\nCurrent users:\n"
        output = None

        # For last dates counters
        month = datetime.now() - timedelta(days=30)
        week = datetime.now() - timedelta(days=7)
        day = datetime.now() - timedelta(days=1)

        # Check where is the utmp file
        if precheck.shouldread("/run/utmp"):
            output = check_output(["utmpdump", "/run/utmp"],
                                  stderr=DEVNULL).decode("utf-8").splitlines()[1:]
        elif precheck.shouldread("/var/run/utmp"):
            output = check_output(["utmpdump", "/var/run/utmp"],
                                  stderr=DEVNULL).decode("utf-8").splitlines()[1:]
        elif precheck.shouldread("/var/log/utmp"):
            output = check_output(["utmpdump", "/var/log/utmp"],
                                  stderr=DEVNULL).decode("utf-8").splitlines()[1:]

        if output:
            logged = 0

            for item in output:
                item = item.split("[")
                item = [x.strip()[:-1].strip() for x in item][1:]
                uttype = int(item[0])  # 5 INIT, 6 LOGIN, 7 USER and 8 DEAD
                pid = int(item[1])
                user = item[3]
                term = item[4]
                origin = item[5]
                date = item[7]

                # Parse common kinds of datetime formats
                # if re.findall("\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", date):
                #    clean = re.findall("\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", date)[0]
                #    datet = datetime.strptime(clean, "%Y-%m-%dT%H:%M:%S")
                # elif re.findall("\D{3} \d{2} \d{2}:\d{2}:\d{2} \d{4}", date):
                #    clean = re.findall("\D{3} \d{2} \d{2}:\d{2}:\d{2} \d{4}", date)[0]
                #    datet = datetime.strptime(clean, "%b %d %H:%M:%S %Y")
                if uttype == 6:
                    detail += " |__({}) - Init with process {}\n".format(date, process[pid][0])
                if uttype == 7:
                    detail += " |__({}) - {} logged on {} from " \
                              "{} using {}\n".format(date, user, term, origin, process[pid][0])
                    logged += 1

            summ += " |__{} users currently logged\n".format(logged)

        if precheck.shouldread("/var/log/wtmp"):
            output = check_output(["utmpdump", "/var/log/wtmp"],
                                  stderr=DEVNULL).decode("utf-8").splitlines()[1:]
            lastusers = []
            originip = []
            monthcounter = 0
            weekcounter = 0
            daycounter = 0
            knownformat = False
            for item in output:
                item = item.split("[")
                item = [x.strip()[:-1].strip() for x in item][1:]
                uttype = int(item[0])  # 5 INIT, 6 LOGIN, 7 USER and 8 DEAD
                user = item[3]
                term = item[4]
                origin = item[5]
                if re.findall("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", origin):
                    ipaddr = ip_address(re.findall("\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}", origin)[0])
                    if ipaddr not in originip:
                        originip.append(ipaddr)
                        report.infrastructure(ipaddr, "Logged")

                date = item[7]
                datet = None
                if re.findall("\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", date):
                    clean = re.findall("\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", date)[0]
                    datet = datetime.strptime(clean, "%Y-%m-%dT%H:%M:%S")

                elif re.findall("\D{3} \d{2} \d{2}:\d{2}:\d{2} \d{4}", date):
                    clean = re.findall("\D{3} \d{2} \d{2}:\d{2}:\d{2} \d{4}", date)[0]
                    datet = datetime.strptime(clean, "%b %d %H:%M:%S %Y")

                if uttype == 7:
                    lastusers.append(" |__({}) - {} logged on {} from {}\n".format(date, user,
                                                                                   term, origin))
                    if datet:
                        knownformat = True
                        if datet > day:
                            daycounter += 1
                            weekcounter += 1
                            monthcounter += 1
                        elif datet > week:
                            weekcounter += 1
                            monthcounter += 1
                        elif datet > month:
                            monthcounter += 1

            if knownformat:
                detail += "\nLast users logged: ({} day, {} week, {} month)\n".format(daycounter,
                                                                                      weekcounter,
                                                                                      monthcounter)
                summ += " |__Users logged last day:{}, " \
                        "last week: {}, last month: {}\n".format(daycounter, weekcounter,
                                                                 monthcounter)
            else:
                detail += "\nLast users logged:\n"

            for item in lastusers[-100:]:
                detail += item

        if precheck.shouldread("/var/log/btmp"):
            detail += "\nFailed logins:\n"
            output = check_output(["utmpdump", "/var/log/btmp"],
                                  stderr=DEVNULL).decode("utf-8").splitlines()
            originip = []
            failedcounter = 0
            monthcounter = 0
            weekcounter = 0
            daycounter = 0
            knownformat = False
            for item in output:
                item = item.split("[")
                item = [x.strip()[:-1].strip() for x in item][1:]
                origin = item[5]
                if re.findall("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", origin):
                    ipaddr = ip_address(re.findall("\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}", origin)[0])
                    if ipaddr not in originip:
                        originip.append(ipaddr)
                        report.infrastructure(ipaddr, "Failed logging")
                date = item[7]
                datet = None

                if re.findall("\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", date):
                    clean = re.findall("\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", date)[0]
                    datet = datetime.strptime(clean, "%Y-%m-%dT%H:%M:%S")

                elif re.findall("\D{3} \d{2} \d{2}:\d{2}:\d{2} \d{4}", date):
                    clean = re.findall("\D{3} \d{2} \d{2}:\d{2}:\d{2} \d{4}", date)[0]
                    datet = datetime.strptime(clean, "%b %d %H:%M:%S %Y")

                failedcounter += 1

                if datet:
                    knownformat = True
                    if datet > day:
                        daycounter += 1
                        weekcounter += 1
                        monthcounter += 1
                    elif datet > week:
                        weekcounter += 1
                        monthcounter += 1
                    elif datet > month:
                        monthcounter += 1

            summ += " |__{} failed logins in btmp, " \
                    "{} from different remote ip\n".format(failedcounter, len(originip))
            detail += " |__{} failed logins in btmp, " \
                      "{} from different remote ip\n".format(failedcounter, len(originip))
            if len(originip) > 0:
                detail += " |__IP fails connection:\n"
                for item in originip:
                    detail += " |       |__{}\n".format(item)

            if knownformat:
                detail += " |__Failed logins last day:{}, " \
                          "last week: {}, last month: {}\n".format(daycounter, weekcounter,
                                                                   monthcounter)

    return summ, detail


def _getdisk(precheck, report):
    detail = detailheader("Disk status information")
    summ = "\nDisk status:\n"
    detail += "Disk load:\n"
    disknames = {}

    for item in listdir("/sys/block"):
        name = None
        for root, dirs, files in walk("/sys/block/{}".format(item)):
            if files:
                if "name" in files:
                    with open("{}/name".format(root)) as f:
                        name = f.read()
        if name:
            disknames[name.strip()] = item

    if precheck.shouldread("/proc/diskstats"):
        with open("/proc/diskstats") as f:
            info = f.readlines()

        if not report.disks:
            report.disks, report.unmounted, report.mounted = _getdisks(precheck)

        diskstat = {}
        for item in info:
            item = " ".join(item.split()).split(" ")
            name = item[2]
            readsectors = int(item[5])
            readtime = int(item[6])
            writesectors = int(item[9])
            writetime = int(item[10])
            diskstat[name] = [readsectors, readtime, writesectors, writetime]

        sleep(1)

        with open("/proc/diskstats") as f:
            info = f.readlines()
            for item in info:
                item = " ".join(item.split()).split(" ")
                name = item[2]
                readsectors = int(item[5])
                readtime = int(item[6])
                writesectors = int(item[9])
                writetime = int(item[10])
                diskstat[name] = [readsectors - diskstat[name][0], readtime - diskstat[name][1],
                                  writesectors - diskstat[name][2], writetime - diskstat[name][3]]

        for item in report.mounted:
            if item[5]:
                total = float(".".join(re.findall(r'\d+', item[1])))
                used = float(".".join(re.findall(r'\d+', item[5])))
                usedratio = round(used * 100 / total)
            else:
                usedratio = 0

            if item[0] in diskstat:
                summ += " |__{} ({}): {} % read and {} " \
                        "% write load. Used {}%\n".format(item[0], item[2],
                                                          diskstat[item[0]][1] / 1000,
                                                          diskstat[item[0]][3] / 1000,
                                                          usedratio)
                detail += " |__{} ({}):\n".format(item[0], item[2])
                detail += " |     |__ {} total size\n".format(item[1])
                detail += " |     |__ {} used size\n".format(item[5])
                detail += " |     |__ {} read sectors/sec\n".format(diskstat[item[0]][0])
                detail += " |     |__ {} write sectors/sec\n".format(diskstat[item[0]][2])
                detail += " |     |__ {} % load reading\n".format(diskstat[item[0]][1] / 1000)
                detail += " |     |__ {} % load writing\n".format(diskstat[item[0]][3] / 1000)
            else:
                newname = disknames.get(item[0], None)
                if newname and newname in diskstat:
                    summ += " |__{} ({}): {} % read and {} " \
                            "% write load. Used {}%\n".format(item[0], item[2],
                                                              diskstat[newname][1] / 1000,
                                                              diskstat[newname][3] / 1000,
                                                              usedratio)
                    detail += " |__{} ({}):\n".format(item[0], item[2])
                    detail += " |     |__ {} total size\n".format(item[1])
                    detail += " |     |__ {} used size\n".format(item[5])
                    detail += " |     |__ {} read sectors/sec\n".format(diskstat[newname][0])
                    detail += " |     |__ {} write sectors/sec\n".format(diskstat[newname][2])
                    detail += " |     |__ {} % load reading\n".format(diskstat[newname][1] / 1000)
                    detail += " |     |__ {} % load writing\n".format(diskstat[newname][3] / 1000)

    if precheck.shouldread("/proc/sys/fs/file-nr"):
        with open("/proc/sys/fs/file-nr") as f:
            data = f.read()
            filenr = data.split()[0]
            filemax = data.split()[2]
            summ += " |__{} allocated file handles of a max of {}\n".format(filenr, filemax)
            detail += " |__{} allocated file handles of a max of {}\n".format(filenr, filemax)

    if precheck.shouldread("/proc/sys/fs/inode-nr"):
        with open("/proc/sys/fs/inode-nr") as f:
            inodenr = f.read().split()[0]
            summ += " |__{} allocated inodes\n".format(inodenr)
            detail += " |__{} allocated inodes\n".format(inodenr)

    return summ, detail


def _getcpu(precheck):
    detail = detailheader("CPU information")
    summ = "\nCPU load average/Uptime:\n"
    detail += "Uptime:\n"

    summ += " |                 |__{} up\n".format(timedelta(seconds=int(uptime)))
    detail += " |__{} up\n".format(timedelta(seconds=int(uptime)))

    if precheck.shouldread("/proc/loadavg"):
        with open("/proc/loadavg") as f:
            info = f.read().split()
        summ += " |__{} 1 min, {} 5 min, {} 15 min\n".format(info[0], info[1], info[2])
        detail += "\nLoad average:\n"
        detail += " |__{} 1 min, {} 5 min, {} 15 min\n".format(info[0], info[1], info[2])

    if precheck.shouldread("/proc/stat"):
        with open("/proc/stat") as f:
            info = f.read().splitlines()
        info = info[0].split()
        usermode = int(info[1])
        nicemode = int(info[2])
        kernelmode = int(info[3])
        idle = int(info[4])
        iowait = int(info[5])
        irq = int(info[6])
        softirq = int(info[7])

        usertime = usermode + nicemode
        irqtime = irq + softirq
        totaltime = usertime + kernelmode + idle + iowait + irqtime
        peruser = round(100 * usertime / totaltime, 2)
        perkernel = round(100 * kernelmode / totaltime, 2)
        peridle = round(100 * idle / totaltime, 2)
        periow = round(100 * iowait / totaltime, 2)
        perirq = round(100 * irqtime / totaltime, 2)
        summ += " |__Since boot: {}% user, {}% kernel, {}% IO wait, {}% IRQ time, " \
                "{}% idle\n".format(peruser, perkernel, periow, perirq, peridle)
        detail += "\n% CPU:\n"
        detail += " |__Since boot: {}% user, {}% kernel, {}% IO wait, {}% IRQ time, " \
                  "{}% idle\n".format(peruser, perkernel, periow, perirq, peridle)

        sleep(1)

        with open("/proc/stat") as f:
            info = f.read().splitlines()
        info = info[0].split()
        usermode = int(info[1]) - usermode
        nicemode = int(info[2]) - nicemode
        kernelmode = int(info[3]) - kernelmode
        idle = int(info[4]) - idle
        iowait = int(info[5]) - iowait
        irq = int(info[6]) - irq
        softirq = int(info[7]) - softirq

        usertime = usermode + nicemode
        irqtime = irq + softirq
        totaltime = usertime + kernelmode + idle + iowait + irqtime
        peruser = round(100 * usertime / totaltime, 2)
        perkernel = round(100 * kernelmode / totaltime, 2)
        peridle = round(100 * idle / totaltime, 2)
        periow = round(100 * iowait / totaltime, 2)
        perirq = round(100 * irqtime / totaltime, 2)
        summ += " |__Now: {}% user, {}% kernel, {}% IO wait, {}% IRQ time, " \
                "{}% idle\n".format(peruser, perkernel, periow, perirq, peridle)
        detail += " |__Now: {}% user, {}% kernel, {}% IO wait, {}% IRQ time, " \
                  "{}% idle\n".format(peruser, perkernel, periow, perirq, peridle)

    return summ, detail


def _getram(precheck):
    detail = detailheader("Memory information")
    summ = "\nCurrent memory status:\n"
    if precheck.shouldread("/proc/meminfo"):
        meminfo = {}

        with open("/proc/meminfo") as f:
            info = f.readlines()

        for item in info:
            if ":" in item:
                name = item.split(":")[0].strip()
                data = item.split(":")[1].strip()
                if "memtotal" in name.lower():
                    meminfo["memtotal"] = round(int(data.split(" ")[0]) / 1024)
                if "memfree" in name.lower():
                    meminfo["memfree"] = round(int(data.split(" ")[0]) / 1024)
                if "memavailable" in name.lower():
                    meminfo["memavailable"] = round(int(data.split(" ")[0]) / 1024)
                if "buffers" in name.lower():
                    meminfo["buffers"] = round(int(data.split(" ")[0]) / 1024)
                if "cached" == name.lower():
                    meminfo["cached"] = round(int(data.split(" ")[0]) / 1024)
                if "swapcached" in name.lower():
                    meminfo["swapcache"] = round(int(data.split(" ")[0]) / 1024)
                if "swaptotal" in name.lower():
                    meminfo["swaptotal"] = round(int(data.split(" ")[0]) / 1024)
                if "swapfree" in name.lower():
                    meminfo["swapfree"] = round(int(data.split(" ")[0]) / 1024)
                if "hardwarecorrupted" in name.lower():
                    meminfo["hardwarecorrupted"] = round(int(data.split(" ")[0]) / 1024)
                if "slab" == name.lower():
                    meminfo["slab"] = round(int(data.split(" ")[0]) / 1024)

        meminfo["totalused"] = meminfo.get("memtotal", 0) - meminfo.get("memfree", 0)
        meminfo["buff/cache"] = (meminfo.get("buffers", 0) + meminfo.get("cached", 0)
                                 + meminfo.get("slab", 0))
        meminfo["reallyused"] = meminfo["totalused"] - meminfo["buff/cache"]
        meminfo["%used"] = round(meminfo["reallyused"] * 100 / meminfo.get("memtotal"))
        meminfo["%buff/cache"] = round(meminfo["buff/cache"] * 100 / meminfo.get("memtotal"))
        meminfo["%free"] = round(meminfo.get("memfree", 0) * 100 / meminfo.get("memtotal"))

        if meminfo.get("swaptotal"):
            meminfo["swapused"] = meminfo.get("swaptotal", 0) - meminfo.get("swapfree", 0)
            meminfo["%swapused"] = round(meminfo["swapused"] * 100 / meminfo.get("swaptotal"))
            meminfo["%swapfree"] = round(meminfo.get("swapfree", 0) * 100 /
                                         meminfo.get("swaptotal"))

        summ += " |__Total memory of {} MB\n".format(meminfo.get("memtotal", 0))
        summ += " |       |__{}% used\n".format(meminfo["%used"])
        summ += " |       |__{}% buffers/cache\n".format(meminfo["%buff/cache"])
        summ += " |       |__{}% free\n".format(meminfo["%free"])
        summ += " |__Total SWAP of {} MB\n".format(meminfo.get("swaptotal", 0))

        if meminfo.get("swaptotal"):
            summ += "         |__{}% used\n".format(meminfo["%swapused"])
            summ += "         |__{}% free\n".format(meminfo["%swapfree"])

        detail += summ
        detail += "\nDetailed memory status:\n"
        detail += " |__Total memory:       {} MB\n".format(meminfo.get("memtotal", 0))
        detail += " |__Memory used:        {} MB\n".format(meminfo["totalused"])
        detail += " |__Memory really used: {} MB\n".format(meminfo["reallyused"])
        detail += " |__Free memory:        {} MB\n".format(meminfo.get("memfree", 0))
        detail += " |__Available memory:   {} MB\n".format(meminfo.get("memavailable", 0))
        detail += " |__Buffers:            {} MB\n".format(meminfo.get("buffers", 0))
        detail += " |__Cached:             {} MB\n".format(meminfo.get("cached", 0))
        detail += " |__Slab:               {} MB\n".format(meminfo.get("slab", 0))
        detail += " |__Buff/Cache/Slab:    {} MB\n".format(meminfo["buff/cache"])
        detail += " |__Hardware corrupted: {} MB\n".format(meminfo.get("hardwarecorrupted", 0))

        if meminfo.get("swaptotal"):
            detail += " |__Total swap:         {} MB\n".format(meminfo.get("swaptotal", 0))
            detail += " |__Free swap:          {} MB\n".format(meminfo.get("swapfree", 0))
            detail += " |__Used swap:          {} MB\n".format(meminfo["swapused"])
            detail += " |__Cached swap:        {} MB\n".format(meminfo["swapcache"])

        return summ, detail


def _getnetdata(precheck, report):
    detail = detailheader("Network live information")
    summ = "\nNetwork connections:\n"
    detail += "\nTCP Connections:\n"

    tcpconnections = []
    udpconnections = []

    if precheck.shouldread("/proc/net/tcp"):
        with open("/proc/net/tcp") as f:
            info = f.readlines()

        for item in info[1:]:
            item = item.strip().split()
            localip, localport = converthex2ipport(item[1])
            remoteip, remoteport = converthex2ipport(item[2])
            constate = tcpstate[int(item[3], 16)]
            uid = int(item[7])
            inode = int(item[9])
            tcpconnections.append([localip, localport, remoteip, remoteport,
                                   constate, report.pidusers[uid], inode])

    if precheck.shouldread("/proc/net/udp"):
        with open("/proc/net/udp") as f:
            info = f.readlines()

        for item in info[1:]:
            item = item.strip().split()
            localip, localport = converthex2ipport(item[1])
            remoteip, remoteport = converthex2ipport(item[2])
            constate = tcpstate[int(item[3], 16)]
            uid = int(item[7])
            inode = int(item[9])
            udpconnections.append([localip, localport, remoteip, remoteport,
                                constate, report.pidusers[uid], inode])

    for item in listdir("/proc"):
        try:
            if re.findall(r'\d+', item):
                for directory in listdir("/proc/{}/fd".format(item)):
                    try:
                        for counter, data in enumerate(tcpconnections):
                            name = "[{}]".format(data[6])
                            if name in readlink("/proc/{}/fd/{}".format(item, directory)):
                                tcpconnections[counter].append(process[int(item)][0])
                                tcpconnections[counter].append(process[int(item)][7])
                    except:
                        pass
                    try:
                        for counter, data in enumerate(udpconnections):
                            name = "[{}]".format(data[6])
                            if name in readlink("/proc/{}/fd/{}".format(item, directory)):
                                udpconnections[counter].append(process[int(item)][0])
                                udpconnections[counter].append(process[int(item)][7])
                    except:
                        pass
        except:
            pass

    tcplisten = 0
    tcpestablished = 0
    tcpwait = 0
    listenports = []

    localmachine = []
    for item in report.ifaces:
        if len(report.ifaces[item]) > 1:
            localmachine.append(report.ifaces[item][1].split("/")[0])

    for item in tcpconnections:
        if len(item) > 7:
            servicename = item[7]
        else:
            servicename = "unknown"

        if precheck.portnames:
            portname = precheck.portnames.get(int(item[1]), ["Unknown service", "Unknown service"])
            portnam2 = precheck.portnames.get(int(item[3]), ["Unknown service", "Unknown service"])
        else:
            portname = ["Unknown service", "Unknown service"]
            portnam2 = ["Unknown service", "Unknown service"]

        if item[4] == tcpstate[10]:
            tcplisten += 1
            listenports.append(item[1])
            if not item[0] == "0.0.0.0":
                report.infrastructure(ip_address(item[0]),
                                      "Port TCP {} ({}) with service {}".format(item[1],
                                                                                portname[0],
                                                                                servicename))
            else:
                for address in localmachine:
                    report.infrastructure(ip_address(address),
                                          "Port TCP {} ({}) with service {}".format(item[1],
                                                                                    portname[0],
                                                                                    servicename))
        elif item[4] == tcpstate[1]:
            tcpestablished += 1
            if item[1] in listenports:
                report.infrastructure(ip_address(item[2]),
                                      "Connected in port {} ({}) of local"
                                      " ip {}".format(item[1], portname[0], item[0]))
            else:
                report.infrastructure(ip_address(item[2]),
                                      "Connected at port {} ({}) from local"
                                      " ip {}".format(item[3], portnam2[0], item[0]))
        elif item[4] == tcpstate[8]:
            tcpwait += 1
            if item[1] in listenports:
                report.infrastructure(ip_address(item[2]),
                                      "Connected in port {} ({}) of local "
                                      "ip {}".format(item[1], portnam2[0], item[0]))
            else:
                report.infrastructure(ip_address(item[2]),
                                      "Connected at port {} ({}) from local "
                                      "ip {}".format(item[3], portnam2[0], item[0]))
        if len(item) > 7:
            detail += " |__{:<21} - {:<21} {:<12} {:<10} {:<12}\n".format(item[0] + ":" + item[1],
                                                                          item[2] + ":" + item[3],
                                                                          item[4], item[5][:10],
                                                                          servicename)
            detail += " |     |__{}\n".format(item[8][:70])
        else:
            detail += " |__{:<21} - {:<21} {:<12} {:<10}\n".format(item[0] + ":" + item[1],
                                                                   item[2] + ":" + item[3],
                                                                   item[4], item[5])

    summ += " |__{} TCP listen ports {}\n".format(tcplisten, listenports)
    summ += " |__{} TCP established connections\n".format(tcpestablished)
    summ += " |__{} TCP sockets in close waiting\n".format(tcpwait)

    udplisten = 0
    udpestablished = 0
    udpwait = 0
    listenports = []

    detail += " O\n\nUDP Connections:\n"
    for item in udpconnections:
        if item[4] == tcpstate[10]:
            udplisten += 1
            listenports.append(item[1])
        elif item[4] == tcpstate[1]:
            udpestablished += 1
        elif item[4] == tcpstate[8]:
            udpwait += 1
        if len(item) > 7:
            detail += " |__{:<21} - {:<21} {:<12} {:<10} {:<12}\n".format(item[0] + ":" + item[1],
                                                                          item[2] + ":" + item[3],
                                                                          item[4], item[5][:10],
                                                                          item[7])
            detail += " |     |__{}\n".format(item[8][:70])
        else:
            detail += " |__{:<21} - {:<21} {:<12} {:<10}\n".format(item[0] + ":" + item[1],
                                                                   item[2] + ":" + item[3],
                                                                   item[4], item[5])
    detail += " O\n"

    summ += " |__{} UDP listen ports {}\n".format(udplisten, listenports)
    summ += " |__{} UDP established connections\n".format(udpestablished)
    summ += " |__{} UDP sockets in close waiting\n".format(udpwait)

    return summ, detail


def getvolatileinfo(report, precheck):
    # Get locale for parse time
    setlocale(LC_TIME, '')

    # Get Processes information
    try:
        report.log("DEBUG", "Processes information gathering started")
        if not report.users:
            _getusers(report, precheck)
        _getprocessdata(report)
        summ, detail = _getprocess()
        report.summarized(3, summ)
        report.detailed(3, detail)
        report.log("DEBUG", "Processes information completed")
    except Exception as e:
        report.log("ERROR", "Can't obtain processes information")
        report.log("DEBUG", str(e))
        report.log("DEBUG", traceback.format_exc())

    # Get RAM live reports
    try:
        report.log("DEBUG", "RAM live information gathering started")
        summ, detail = _getram(precheck)
        report.summarized(3, summ)
        report.detailed(3, detail)
        report.log("DEBUG", "RAM live information completed")
    except Exception as e:
        report.log("ERROR", "Can't obtain RAM live information")
        report.log("DEBUG", str(e))
        report.log("DEBUG", traceback.format_exc())

    # Get CPU live reports
    try:
        report.log("DEBUG", "CPU live information gathering started")
        summ, detail = _getcpu(precheck)
        report.summarized(3, summ)
        report.detailed(3, detail)
        report.log("DEBUG", "CPU live information completed")
    except Exception as e:
        report.log("ERROR", "Can't obtain CPU live information")
        report.log("DEBUG", str(e))
        report.log("DEBUG", traceback.format_exc())

    # Get disk live reports
    try:
        report.log("DEBUG", "Disk live information gathering started")
        summ, detail = _getdisk(precheck, report)
        report.summarized(3, summ)
        report.detailed(3, detail)
        report.log("DEBUG", "Disk live information completed")
    except Exception as e:
        report.log("ERROR", "Can't obtain Disk live information")
        report.log("DEBUG", str(e))
        report.log("DEBUG", traceback.format_exc())

    # Get users live reports
    try:
        report.log("DEBUG", "User live information gathering started")
        summ, detail = _getuserdata(precheck, report)
        report.summarized(3, summ)
        report.detailed(3, detail)
        report.log("DEBUG", "User live information completed")
    except Exception as e:
        report.log("ERROR", "Can't obtain User live information")
        report.log("DEBUG", str(e))
        report.log("DEBUG", traceback.format_exc())

    # Get network live reports
    try:
        report.log("DEBUG", "Network live information gathering started")
        if not report.ifaces:
            _getnetinfo(report, precheck)
        summ, detail = _getnetdata(precheck, report)
        report.summarized(3, summ)
        report.detailed(3, detail)
        report.log("DEBUG", "Network live information completed")
    except Exception as e:
        report.log("ERROR", "Can't obtain network live information")
        report.log("DEBUG", str(e))
        report.log("DEBUG", traceback.format_exc())
