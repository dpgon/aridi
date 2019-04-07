from os import uname, walk, stat
from platform import libc_ver
from traceback import format_exc
from subprocess import check_output, DEVNULL, CalledProcessError
from utils import detailheader, detailfile


def _getusb():
    summ = "\nUSB devices:"
    detail = detailheader("USB information")
    linuxroot = []
    hub = []
    usb = []
    total = []

    output = check_output("lsusb").decode("utf-8").splitlines()

    for item in output:
        bus = item.split(':')[0].lower().replace("bus ", "").replace(" device ", ":")
        usbid = item.split('ID ')[1][:9]
        name = item.split('ID ')[1][10:]
        if "1d6b:000" in usbid.lower():
            linuxroot.append([usbid, name, bus])
        elif "hub" in name.lower():
            hub.append([usbid, name, bus])
        else:
            usb.append([usbid, name, bus])
        total.append([usbid, name, bus])

    summ += " |__{} devices\n |__{} hubs " \
            "(Linux root hubs included)\n".format(len(usb), len(linuxroot) + len(hub))
    helptext = "(device ID - name - bus:device)"
    detail += "{:^80}\n".format(helptext)

    detail += "Linux root hubs:\n"
    for item in linuxroot:
        detail += " |__{} - {} - {}\n".format(item[0], item[1], item[2])
    detail += "\nOther hubs:\n"
    for item in hub:
        detail += " |__{} - {} - {}\n".format(item[0], item[1], item[2])
    detail += "\nUSB devices:\n"
    for item in usb:
        detail += " |__{} - {} - {}\n".format(item[0], item[1], item[2])

    return summ, detail, total


def _gethardware(precheck):
    arch = uname().machine
    detail = ""
    summ = "\nCPU and memory information:\n"
    cpuinfo = {"processor": 0,
               "vendor_id": "",
               "cpu_family": 0,
               "model": 0,
               "model_name": "",
               "stepping": 0,
               "physical_id": 0,
               "cpu_cores": 0,
               "flags": "",
               "bugs": ""}
    meminfo = {"memtotal": "", "swaptotal": ""}

    if precheck.shouldread("/proc/cpuinfo"):
        detail += detailheader("CPU information")

        with open("/proc/cpuinfo") as f:
            info = f.readlines()

        for item in info:
            if ":" in item:
                name = item.split(":")[0].strip()
                data = item.split(":")[1].strip()
                if "processor" in name:
                    number = int(data)
                    if number > cpuinfo["processor"]:
                        cpuinfo["processor"] = number
                if "vendor" in name:
                    cpuinfo["vendor_id"] = data
                if "cpu family" in name:
                    number = int(data)
                    if number > cpuinfo["cpu_family"]:
                        cpuinfo["cpu_family"] = number
                if name == "model":
                    number = int(data)
                    if number > cpuinfo["model"]:
                        cpuinfo["model"] = number
                if "model name" in name:
                    cpuinfo["model_name"] = data
                if "stepping" in name:
                    number = int(data)
                    if number > cpuinfo["stepping"]:
                        cpuinfo["stepping"] = number
                if "physical" in name:
                    number = int(data)
                    if number > cpuinfo["physical_id"]:
                        cpuinfo["physical_id"] = number
                if "cpu cores" in name:
                    number = int(data)
                    if number > cpuinfo["cpu_cores"]:
                        cpuinfo["cpu_cores"] = number
                if "flags" in name:
                    cpuinfo["flags"] = data
                if "bugs" in name:
                    cpuinfo["bugs"] = data
        cpuinfo['processor'] += 1
        cpuinfo['physical_id'] += 1
        summ += " |__Architecture: {}\n |__CPU: {} x {}\n |     |__{} stepping {} with {} " \
                "cores\n".format(arch, cpuinfo["physical_id"],
                                 cpuinfo["vendor_id"], cpuinfo["model_name"],
                                 cpuinfo["stepping"], cpuinfo["cpu_cores"])
        detail += "Architect.: {}\nSockets:    {}\n".format(arch, cpuinfo["physical_id"])
        detail += "Vendor:     {}\nModel name: {}\nModel:      {}\n".format(cpuinfo["vendor_id"],
                                                                            cpuinfo["model_name"],
                                                                            cpuinfo["model"])
        detail += "Stepping:   {}\nCores/sock: {}\nThreads:    {}\n".format(cpuinfo["stepping"],
                                                                            cpuinfo["cpu_cores"],
                                                                            cpuinfo["processor"])
        detail += "CPU Family: {}\nFlags:      {}\nBugs:       {}\n".format(cpuinfo["cpu_family"],
                                                                            cpuinfo["flags"],
                                                                            cpuinfo["bugs"])

    if precheck.shouldread("/proc/meminfo"):
        detail += detailheader("RAM information")

        with open("/proc/meminfo") as f:
            info = f.readlines()

        for item in info:
            if ":" in item:
                name = item.split(":")[0].strip()
                data = item.split(":")[1].strip()
                if "memtotal" in name.lower():
                    meminfo["memtotal"] = data
                if "swaptotal" in name.lower():
                    meminfo["swaptotal"] = data

        summ += " |__Memory: {}\n |__SWAP: {}\n".format(meminfo["memtotal"], meminfo["swaptotal"])
        detail += "Memory:     {}\nSWAP:       {}\n".format(meminfo["memtotal"],
                                                            meminfo["swaptotal"])

    return summ, detail, cpuinfo, meminfo


def _getos():
    info = uname()
    data = "{} {} {}".format(info.sysname, info.release, info.version)
    summ = "\nOS Kernel information:\n |__{}\n".format(data)
    detail = detailheader("OS Kernel information")
    detail += "{}\n".format(data)
    return summ, detail, data


def _getdistrorelease(precheck):
    name = ''
    version = ''
    filename = ''
    data = ''
    summ = '\nOS Release information:\n'
    detail = detailheader("OS Release information")

    # this is the current systemd version info
    if precheck.shouldread('/etc/os-release'):
        lines = open('/etc/os-release').read().split('\n')
        detail += detailfile('/etc/os-release')
        for line in lines:
            detail += line + "\n"
            if line.startswith('NAME='):
                name = line.split('=')[1]
                if name[0] == '"' and name[-1] == '"':
                    name = name[1:-1]
            if line.startswith('VERSION='):
                version = line.split('=')[1]
                if version[0] == '"' and version[-1] == '"':
                    version = version[1:-1]
        data = name + " " + version
        summ += " |__{}\n".format(data)
    # and now, the other release info files
    elif precheck.shouldread('/etc/centos-release'):
        filename = '/etc/centos-release'
    elif precheck.shouldread('/etc/lsb-release'):
        lines = open('/etc/lsb-release').read().split('\n')
        detail += detailfile('/etc/lsb-release')
        for line in lines:
            detail += line + "\n"
            if line.startswith('DISTRIB_ID='):
                name = line.split('=')[1]
                if name[0] == '"' and name[-1] == '"':
                    name = name[1:-1]
            if line.startswith('DISTRIB_RELEASE='):
                version = line.split('=')[1]
                if version[0] == '"' and version[-1] == '"':
                    version = version[1:-1]
        data = name + " " + version
        summ += " |__{}\n".format(data)
    elif precheck.shouldread('/suse/etc/SuSE-release'):
        filename = '/suse/etc/SuSE-release'
    elif precheck.shouldread('/etc/redhat-release'):
        filename = '/etc/redhat-release'
    elif precheck.shouldread('/etc/fedora-release'):
        filename = '/etc/fedora-release'

    if filename:
        name = open(filename).read()
        data = name.split('\n')[0]
        summ += " |__{}\n".format(data)
        detail += filename + '-'*len(filename) + name + "\n"

    # check old distribution version info
    if precheck.shouldread('/etc/debian-version'):
        other_version = open('/etc/debian-version').read()
        summ += " |__Debian version: " + other_version.split('\n')[0] + "\n"
        detail += detailfile('/etc/debian-version')
        detail += other_version + "\n"
    elif precheck.shouldread('/etc/slackware-version'):
        other_version = open('/etc/slackware-version').read()
        summ += " |__Slackware version: " + other_version.split('\n')[0] + "\n"
        detail += detailfile('/etc/slackware-version')
        detail += other_version + "\n"

    return summ, detail, data


def _getlibc():
    summ = "\nLibc version:\n |__{} {}\n".format(libc_ver()[0], libc_ver()[1])
    detail = detailheader("Libc information")
    detail += "{} {}\n".format(libc_ver()[0], libc_ver()[1])
    return summ, detail


def _getdisks(precheck):
    disks = []
    mounted = []
    unmounted = []
    repeated = []

    # check disks and parts with lsblk
    if precheck.checkcommand("lsblk"):
        outputlsblk = check_output(["lsblk", "-l"]).decode("utf-8").splitlines()[1:]
        for item in outputlsblk:
            spacefree = " ".join(item.split()).split(" ")
            name = spacefree[0]
            blktype = spacefree[5]
            size = spacefree[3]
            mountpoint = "".join(spacefree[6:])

            if name not in repeated:
                repeated.append(name)
                if blktype == "disk" or blktype == "dmraid":
                    disks.append([name, size])
                elif blktype == "part":
                    if mountpoint:
                        mounted.append([name, size, mountpoint, [], [], []])
                    else:
                        unmounted.append([name, size])

    # check findmnt output
    if precheck.checkcommand("findmnt"):
        outputfindmnt = check_output(["findmnt", "-l"]).decode("utf-8").splitlines()[1:]
        for item in outputfindmnt:
            spacefree = " ".join(item.split()).split(" ")
            target = spacefree[0]
            try:
                options = spacefree[3]
                fstype = spacefree[2]
            except IndexError:
                options = spacefree[2]
                fstype = spacefree[1]

            for part in range(len(mounted)):
                if mounted[part][2] == target:
                    mounted[part][3] = fstype
                    mounted[part][4] = options
                    try:
                        output = check_output(["df", mounted[part][2], "-h"],
                                              stderr=DEVNULL).decode("utf-8").splitlines()[1]
                    except CalledProcessError as e:
                        output = e.output.decode("utf-8").splitlines()[1]
                    mounted[part][5] = " ".join(output.split()).split(" ")[2]

    return disks, unmounted, mounted


def _checkpermissions(precheck, report):
    stickydirs = []
    alluserwrite = []
    readerrors = []
    suidperm = []
    guidperm = []

    # Check directories with write permissions and sticky bit
    for root, dirs, files in walk("/"):
        if files:
            init = root.split("/")[1]
            if init not in ["dev", "proc", "sys", "run"]:
                for item in files:
                    filename = root + "/" + item
                    try:
                        perm = stat(filename)
                        if perm.st_uid == 0:
                            ownerroot = True
                        else:
                            ownerroot = False
                        if perm.st_gid == 0:
                            grouproot = True
                        else:
                            grouproot = False
                        perm = perm.st_mode
                        writeall = perm & 0o2
                        suid = perm & 0o4000
                        sgid = perm & 0o2000
                        if writeall:
                            alluserwrite.append(filename)
                        if suid:
                            suidperm.append([filename, ownerroot])
                        if sgid:
                            guidperm.append([filename, grouproot])
                    except Exception as e:
                        readerrors.append(str(e))
        if dirs:
            for item in dirs:
                filename = root + "/" + item
                try:
                    perm = stat(filename).st_mode
                    writeall = perm & 0o2
                    sticky = perm & 0o1000
                    if writeall and not sticky:
                        stickydirs.append(filename)
                except Exception as e:
                    readerrors.append(str(e))

    return stickydirs, alluserwrite, readerrors, suidperm, guidperm


def _getzypper():
    packages = []
    output = check_output(["zypper", "packages", "--installed-only"]).decode("utf-8").splitlines()
    for item in output:
        if item[0] == "i":
            name = item.split("|")[2].strip()
            version = item.split("|")[3].strip()
            if [name, version] not in packages:
                packages.append([name, version])
    return packages


def _getyum():
    packages = []
    output = check_output(["yum", "list",
                           "installed", "--noplugins"]).decode("utf-8").splitlines()[1:]
    output = " ".join(output)
    output = " ".join(output.split()).split(" ")

    for item in range(0, len(output), 3):
        packages.append([output[item], output[item+1]])

    return packages


def _getpacman():
    packages = []
    output = check_output(["pacman", "-Q"]).decode("utf-8").splitlines()
    for item in output:
        packages.append(item.split(" "))
    return packages


def _getapt():
    packages = []
    output = check_output(["apt", "list", "--installed"]).decode("utf-8").splitlines()
    for item in output:
        if "[" in item:
            name = item.split(" ")[0].split("/")[0]
            version = item.split(" ")[1]
            packages.append([name, version])
    return packages


def _getdpkg():
    packages = []
    output = check_output(["dpkg-query", "-f",
                           "${binary:Package}\t${source:Version}\n",
                           "-W"]).decode("utf-8").splitlines()
    for item in output:
        name = item.split("\t")[0]
        if ":" in name:
            name = name.split(":")[0]
        version = item.split("\t")[1]
        if [name, version] not in packages:
            packages.append([name, version])
    return packages


def getgeneralinfo(report, precheck):

    # Get hardware reports
    try:
        report.log("DEBUG", "CPU and RAM information gathering started")
        summ, detail, cpuinfo, meminfo = _gethardware(precheck)
        report.summarized(1, summ)
        report.detailed(1, detail)
        report.cpuinfo = cpuinfo
        report.meminfo = meminfo
        report.log("DEBUG", "CPU and RAM information completed")
    except Exception as e:
        report.log("ERROR", "Can't obtain CPU and RAM information")
        report.log("DEBUG", str(e))
        report.log("DEBUG", format_exc())

    try:
        report.log("DEBUG", "USB information gathering started")
        summ, detail, total = _getusb()
        report.summarized(1, summ)
        report.detailed(1, detail)
        report.total = total
        report.log("DEBUG", "USB information completed")
    except Exception as e:
        report.log("ERROR", "Can't obtain usb information")
        report.log("DEBUG", str(e))
        report.log("DEBUG", format_exc())

    # Get OS reports
    try:
        report.log("DEBUG", "Kernel information gathering started")
        summ, detail, data = _getos()
        report.summarized(1, summ)
        report.detailed(1, detail)
        report.oskernel = data
        report.log("DEBUG", "Kernel information completed")
    except Exception as e:
        report.log("ERROR", "Can't obtain OS uname information")
        report.log("DEBUG", str(e))
        report.log("DEBUG", format_exc())

    try:
        report.log("DEBUG", "Distribution release information gathering started")
        summ, detail, data = _getdistrorelease(precheck)
        report.summarized(1, summ)
        report.detailed(1, detail)
        report.osdistro = data
        report.log("DEBUG", "Distribution release information completed")
    except Exception as e:
        report.log("ERROR", "Can't obtain distribution release information")
        report.log("DEBUG", str(e))
        report.log("DEBUG", format_exc())

    try:
        report.log("DEBUG", "libc information gathering started")
        summ, detail = _getlibc()
        report.summarized(1, summ)
        report.detailed(1, detail)
        report.log("DEBUG", "libc information completed")
    except Exception as e:
        report.log("ERROR", "Can't obtain libc information")
        report.log("DEBUG", str(e))
        report.log("DEBUG", format_exc())

    # Get software reports
    try:
        report.log("DEBUG", "Software packages gathering started")

        summ = "\nPackages manager not found\n"
        if precheck.checkcommand("yum"):
            precheck.packages = _getyum()
            summ = "\nTotal RPM packages (yum):\n |__{}\n".format(len(precheck.packages))
        elif precheck.checkcommand("dpkg-query"):
            precheck.packages = _getdpkg()
            summ = "\nTotal DEB packages (dpkg):\n |__{}\n".format(len(precheck.packages))
        elif precheck.checkcommand("zypper"):
            precheck.packages = _getzypper()
            summ = "\nTotal RPM packages (zypper):\n |__{}\n".format(len(precheck.packages))
        elif precheck.checkcommand("apt"):
            precheck.packages = _getapt()
            summ = "\nTotal DEB packages (apt):\n |__{}\n".format(len(precheck.packages))
        elif precheck.checkcommand("pacman"):
            precheck.packages = _getpacman()
            summ = "\nTotal pkg.tar.xz packages (pacman):\n |__{}\n".format(len(precheck.packages))

        report.summarized(1, summ)
        report.detailed(1, detailheader("Packages information"))
        for item in precheck.packages:
            report.detailed(1, "{:32s} - {}\n".format(item[0], item[1]))

        report.log("DEBUG", "Software packages information completed")

    except Exception as e:
        report.log("ERROR", "Can't obtain software packages information")
        report.log("DEBUG", str(e))
        report.log("DEBUG", format_exc())

    # Get filesystem reports
    try:
        report.log("DEBUG", "disk information gathering started")
        report.disks, report.unmounted, report.mounted = _getdisks(precheck)
        summ = "\nPartitions mounted:\n"
        for item in report.mounted:
            if "swap" in item[2].lower():
                summ += " |__{:_<32}__SWAP filesystem with {}\n".format(item[2], item[1])
            else:
                summ += " |__{:_<32}__{} filesystem with {}, used {}\n".format(item[2],
                                                                               item[3],
                                                                               item[1],
                                                                               item[5])
        report.summarized(1, summ)

        detail = detailheader("Disk/Partitions information")
        detail += detailfile("Disks info:")
        for item in report.disks:
            detail += "{:32s} - Size: {}\n".format(item[0], item[1])
        detail += detailfile("Unmounted partitions:")
        for item in report.unmounted:
            detail += "{:32s} - Size: {}\n".format(item[0], item[1])
        detail += detailfile("Mounted partitions:")
        for item in report.mounted:
            detail += "\n{:32s}\n |__{}\n".format(item[0], item[2])
            if "swap" in item[2].lower():
                detail += " |__Size: {}\n".format(item[1])
            else:
                detail += " |__Filesystem: {}\n |__Size: {}, used {}\n".format(item[3],
                                                                               item[1],
                                                                               item[5])
                detail += " |__Options: {}\n".format(item[4])

        report.detailed(1, detail)
        report.log("DEBUG", "disk information completed")
    except Exception as e:
        report.log("ERROR", "Can't obtain disk information")
        report.log("DEBUG", str(e))
        report.log("DEBUG", format_exc())

    try:
        report.log("DEBUG", "File and directory permission information gathering started")
        print("\naridy.py could search the filesystem in order to locate directories with no "
              "StickyBit and all users write permission, or files with SUID or GUID, but "
              "it could be very slow. Do you want to proceed? (y/N) ", end="")
        ans = str(input()).lower().lstrip()
        if len(ans) == 0 or 'y' not in ans[0]:
            return
        stickydirs, alluserwrite, readerrors, suidperm, guidperm = _checkpermissions(precheck,
                                                                                     report)
        report.stickydirs = stickydirs
        report.alluserwrite = alluserwrite
        report.readerrors = readerrors
        report.suidperm = suidperm
        report.guidperm = guidperm
        report.detailed(1, detailheader("File/Dir information"))
        report.summarized(1, "\nFile and directories information:\n")
        report.detailed(1, "File and directories information:\n")
        report.summarized(1, " |__StickyBit: Found {} dirs with all users write "
                             "permission and no stickybit\n".format(len(stickydirs)))
        report.detailed(1, " |__StickyBit: Found {} dirs with all users write permission and "
                           "no stickybit.\n |   You should put the sticky bit in order to avoid "
                           "any user can modify files\n |   of other "
                           "users\n".format(len(stickydirs)))
        report.summarized(1, " |__All users can write: Found {} files with all "
                             "users write permission\n".format(len(alluserwrite)))
        report.detailed(1, " |__All users can write: Found {} files with all users write "
                           "permission.\n |   Is it necessary?\n".format(len(alluserwrite)))
        report.summarized(1, " |__Read errors: Found {} files or directories with "
                             "errors\n".format(len(readerrors)))
        report.detailed(1, " |__Read errors: Found {} files or directories with errors. There "
                           "are\n |   possible bad links, maybe you want to delete "
                           "them\n".format(len(readerrors)))
        report.summarized(1, " |__SUID: Found {} files with SUID "
                             "permission\n".format(len(suidperm)))
        report.detailed(1, " |__SUID: Found {} files with SUID permission. Are they "
                           "necessary?\n".format(len(suidperm)))
        report.summarized(1, " |__GUID: Found {} files with GUID "
                             "permission\n".format(len(guidperm)))
        report.detailed(1, " |__GUID: Found {} files with GUID permission. Are they "
                           "necessary?\n".format(len(guidperm)))

        try:
            f = open("aridi.badfiles", "w")
            for item in stickydirs:
                f.write("'{}' dir has write permission for all user and "
                        "no sticky bit\n".format(item))
            for item in alluserwrite:
                f.write("'{}' file has write permission for all user\n".format(item))
            for item in readerrors:
                f.write("{}\n".format(item))
            for item in suidperm:
                if item[1]:
                    f.write("'{}' file has SUID and it's owned by the root user".format(item[0]))
                else:
                    f.write("'{}' file has SUID. Is it necessary?".format(item[0]))
            for item in guidperm:
                if item[1]:
                    f.write("'{}' file has GUID and it's owned by the root group".format(item[0]))
                else:
                    f.write("'{}' file has GUID. Is it necessary?".format(item[0]))
        except Exception as e:
            report.log("ERROR", "Can't write aridy.badfiles")
            report.log("DEBUG", str(e))
            report.log("DEBUG", format_exc())
        finally:
            f.close()
        report.log("DEBUG", "File and directory permission information completed")
    except Exception as e:
        report.log("ERROR", "Can't obtain file and directory permission information")
        report.log("DEBUG", str(e))
        report.log("DEBUG", format_exc())
