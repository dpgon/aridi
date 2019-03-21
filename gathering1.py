from os import uname, walk, stat
from platform import libc_ver
import traceback
import subprocess
import json


def _getusb():
    detail = "\n===============\nUSB information\n===============\n"
    linuxroot = []
    hub = []
    usb = []
    total = []

    output = subprocess.check_output("lsusb").decode("utf-8").splitlines()

    for item in output:
        bus = item.split(':')[0].lower().replace("bus ", "").replace(" device ", ":")
        id = item.split('ID ')[1][:9]
        name = item.split('ID ')[1][10:]
        if "1d6b:000" in id.lower():
            linuxroot.append([id, name, bus])
        elif "hub" in name.lower():
            hub.append([id, name, bus])
        else:
            usb.append([id, name, bus])
        total.append([id, name, bus])

    sum = "USB devices: {} devices and {} hubs (Linux root hubs included)\n".format(len(usb),
                                                                    len(linuxroot) + len(hub))
    detail += "(device ID - name - bus:device)\n"
    detail += "Linux root hubs:\n"
    for item in linuxroot:
        detail += "  {} - {} - {}\n".format(item[0], item[1], item[2])
    detail += "Other hubs:\n"
    for item in hub:
        detail += "  {} - {} - {}\n".format(item[0], item[1], item[2])
    detail += "USB devices:\n"
    for item in usb:
        detail += "  {} - {} - {}\n".format(item[0], item[1], item[2])

    return sum, detail, total


def _gethardware(precheck):
    arch = uname().machine
    detail = ""
    sum = ""
    if precheck.shouldread("/proc/cpuinfo"):
        detail += "\n===============\nCPU information\n===============\n"
        cpuinfo = { "processor" : 0,
                    "vendor_id" : "",
                    "cpu_family" : 0,
                    "model" : 0,
                    "model_name" : "",
                    "stepping" : 0,
                    "physical_id" : 0,
                    "cpu_cores" : 0,
                    "flags" : "",
                    "bugs" : ""}

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
        sum += "Architecture: {}\nCPU: {} x {} {} stepping {} with {} cores\n".format(arch,
                                                        cpuinfo["physical_id"], cpuinfo["vendor_id"],
                                                        cpuinfo["model_name"], cpuinfo["stepping"],
                                                        cpuinfo["cpu_cores"])
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
        detail += "\n===============\nRAM information\n===============\n"
        meminfo = {"memtotal": "", "swaptotal": ""}

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

        sum += "Memory: {}\nSWAP: {}\n".format(meminfo["memtotal"], meminfo["swaptotal"])
        detail += "Memory:     {}\nSWAP:       {}\n".format(meminfo["memtotal"],
                                                            meminfo["swaptotal"])

    return sum, detail, cpuinfo, meminfo


def _getos():
    info = uname()
    data = info.sysname + " " + info.release + " " +info.version
    sum = "OS information: {}\n".format(data)
    detail = "\n=====================\nOS Kernel information\n=====================\n"
    detail += sum
    return sum, detail, data


def _getdistrorelease(precheck):
    name = ''
    version = ''
    filename = ''
    data = ''
    sum = ''
    detail = "\n======================\nOS Release information\n======================\n"

    # this is the current systemd version info
    if precheck.shouldread('/etc/os-release'):
        lines = open('/etc/os-release').read().split('\n')
        detail += '/etc/os-release\n---------------\n'
        for line in lines:
            detail += line + "\n"
            if line.startswith('NAME='):
                name = line.split('=')[1]
                if name[0]=='"' and name[-1]=='"':
                    name = name[1:-1]
            if line.startswith('VERSION='):
                version = line.split('=')[1]
                if version[0]=='"' and version[-1]=='"':
                    version = version[1:-1]
        data = name + " " + version
        sum = "OS Release information: " + data + "\n"
    # and now, the other release info files
    elif precheck.shouldread('/etc/lsb-release'):
        lines = open('/etc/lsb-release').read().split('\n')
        detail += '/etc/lsb-release\n----------------\n'
        for line in lines:
            detail += line + "\n"
            if line.startswith('DISTRIB_ID='):
                name = line.split('=')[1]
                if name[0]=='"' and name[-1]=='"':
                    name = name[1:-1]
            if line.startswith('DISTRIB_RELEASE='):
                version = line.split('=')[1]
                if version[0]=='"' and version[-1]=='"':
                    version = version[1:-1]
        data = name + " " + version
        sum = "OS Release information: " + data + "\n"
    elif precheck.shouldread('/suse/etc/SuSE-release'):
        filename = '/suse/etc/SuSE-release'
    elif precheck.shouldread('/etc/redhat-release'):
        filename = '/etc/redhat-release'
    elif precheck.shouldread('/etc/centos-release'):
        filename = '/etc/centos-release'
    elif precheck.shouldread('/etc/fedora-release'):
        filename = '/etc/fedora-release'

    if filename:
        name = open(filename).read()
        data = name.split('\n')[0]
        sum = "OS Release information: " + data + "\n"
        detail += filename + '-'*len(filename) + name + "\n"

    # check old distribution version info
    if precheck.shouldread('/etc/debian-version'):
        other_version = open('/etc/debian-version').read()
        sum += "Debian version: " + other_version.split('\n')[0] + "\n"
        detail += '/etc/debian-version\n-------------------\n' + other_version + "\n"
    elif precheck.shouldread('/etc/slackware-version'):
        other_version = open('/etc/slackware-version').read()
        sum += "Slackware version: " + other_version.split('\n')[0] + "\n"
        detail += '/etc/slackware-version\n-------------------\n' + other_version + "\n"

    return sum, detail, data


def _getlibc():
    sum = "Libc information: " + libc_ver()[0] + " " + libc_ver()[1] + "\n"
    detail = "\n================\nLibc information\n================\n"
    detail += sum
    return sum, detail


def _getdisks():
    disks = []
    mounted = []
    unmounted = []
    repeated = []

    # check disks and parts with lsblk
    outputlsblk = json.loads(subprocess.check_output(["lsblk", "-J", "-l"]).decode("utf-8"))
    outputlsblk = outputlsblk["blockdevices"]
    for item in outputlsblk:
        if item["name"] not in repeated:
            repeated.append(item["name"])
            if item["type"] == "disk" or item["type"] == "dmraid":
                disks.append([item["name"], item["size"]])
            elif item["type"] == "part":
                if item["mountpoint"]:
                    mounted.append([item["name"], item["size"], item["mountpoint"], [], [], []])
                else:
                    unmounted.append([item["name"], item["size"]])

    # check findmnt output
    outputfindmnt = json.loads(subprocess.check_output(["findmnt", "-J", "-l"]).decode("utf-8"))
    outputfindmnt = outputfindmnt["filesystems"]
    for item in outputfindmnt:
        for part in range(len(mounted)):
            if mounted[part][2] == item["target"]:
                mounted[part][3] = item["fstype"]
                mounted[part][4] = item["options"]
                try:
                    output = subprocess.check_output(["du", mounted[part][2], "-shx"], stderr=subprocess.DEVNULL).decode("utf-8")
                except subprocess.CalledProcessError as e:
                    output = e.output.decode("utf-8")
                mounted[part][5] = output.split("\t")[0]

    return disks, unmounted, mounted


def _checkpermissions(precheck):
    stickydirs = []
    alluserwrite = []
    readerrors = []
    suidperm = []
    guidperm = []

    # Check incorrect permissions
    incorrect = precheck.dangerousperm()

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


def _getpacman():
    packages = []
    output = subprocess.check_output(["pacman", "-Q"]).decode("utf-8").splitlines()
    for item in output:
        packages.append(item.split(" "))
    return packages


def _getapt():
    packages = []
    output = subprocess.check_output(["apt", "list", "--installed"]).decode("utf-8").splitlines()
    for item in output:
        if "[" in item:
            name = item.split(" ")[0].split("/")[0]
            version = item.split(" ")[1]
            packages.append([name, version])
    return packages


def _getdpkg():
    packages = []
    output = subprocess.check_output(["dpkg-query", "-f",
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
    """
    # Get hardware reports
    try:
        report.log("DEBUG", "CPU and RAM information gathering started")
        sum, detail, cpuinfo, meminfo = _gethardware(precheck)
        report.summarized(1, sum)
        report.detailed(1, detail)
        report.cpuinfo = cpuinfo
        report.meminfo = meminfo
        report.log("DEBUG", "CPU and RAM information completed")
    except Exception as e:
        report.log("ERROR", "Can't obtain CPU and RAM information")
        report.log("DEBUG", str(e))
        report.log("DEBUG", traceback.format_exc())

    try:
        report.log("DEBUG", "USB information gathering started")
        sum, detail, total = _getusb()
        report.summarized(1, sum)
        report.detailed(1, detail)
        report.total = total
        report.log("DEBUG", "USB information completed")
    except Exception as e:
        report.log("ERROR", "Can't obtain usb information")
        report.log("DEBUG", str(e))
        report.log("DEBUG", traceback.format_exc())

    # Get OS reports
    try:
        report.log("DEBUG", "Kernel information gathering started")
        sum, detail, data = _getos()
        report.summarized(1, sum)
        report.detailed(1, detail)
        report.oskernel = data
        report.log("DEBUG", "Kernel information completed")
    except Exception as e:
        report.log("ERROR", "Can't obtain OS uname information")
        report.log("DEBUG", str(e))
        report.log("DEBUG", traceback.format_exc())

    try:
        report.log("DEBUG", "Distribution release information gathering started")
        sum, detail, data =_getdistrorelease(precheck)
        report.summarized(1, sum)
        report.detailed(1, detail)
        report.osdistro = data
        report.log("DEBUG", "Distribution release information completed")
    except Exception as e:
        report.log("ERROR", "Can't obtain distribution release information")
        report.log("DEBUG", str(e))
        report.log("DEBUG", traceback.format_exc())

    try:
        report.log("DEBUG", "libc information gathering started")
        sum, detail = _getlibc()
        report.summarized(1, sum)
        report.detailed(1, detail)
        report.log("DEBUG", "libc information completed")
    except Exception as e:
        report.log("ERROR", "Can't obtain libc information")
        report.log("DEBUG", str(e))
        report.log("DEBUG", traceback.format_exc())

    # Get filesystem reports
    try:
        report.log("DEBUG", "disk information gathering started")
        disks, unmounted, mounted = _getdisks()
        report.disks = disks
        report.unmounted = unmounted
        report.mounted = mounted
        sum = "Partitions mounted:\n"
        for item in mounted:
            if "swap" in item[2].lower():
                sum += "{:32s} - Filesystem: SWAP - Size: {}\n".format(item[2], item[1])
            else:
                sum += "{:32s} - Filesystem: {} - Size: {}, used {}\n".format(item[2],
                                                                              item[3],
                                                                              item[1],
                                                                              item[5])
        report.summarized(1, sum)

        detail = "\n===========================\nDisk/Partitions information\n" \
                 "===========================\n"
        detail += "Disks info:\n-----------\n"
        for item in disks:
            detail += "{:32s} - Size: {}\n".format(item[0], item[1])
        detail += "\nUnmounted partitions:\n---------------------\n"
        for item in unmounted:
            detail += "{:32s} - Size: {}\n".format(item[0], item[1])
        detail += "\nMounted partitions:\n-------------------\n"
        for item in mounted:
            detail += "{:32s}\n   |__{}\n".format(item[0], item[2])
            if "swap" in item[2].lower():
                detail += "   |__Size: {}\n".format(item[1])
            else:
                detail += "   |__Filesystem: {}\n   |__Size: {}, used {}\n".format(item[3], item[1], item[5])
                detail += "   |__Options: {}\n".format(item[4])

        report.detailed(1, detail)
        report.log("DEBUG", "disk information completed")
    except Exception as e:
        report.log("ERROR", "Can't obtain disk information")
        report.log("DEBUG", str(e))
        report.log("DEBUG", traceback.format_exc())

    try:
        report.log("DEBUG", "File and directory permission information gathering started")
        stickydirs, alluserwrite, readerrors, suidperm, guidperm = _checkpermissions(precheck)
        report.stickydirs = stickydirs
        report.alluserwrite = alluserwrite
        report.readerrors = readerrors
        report.suidperm = suidperm
        report.guidperm = guidperm
        report.detailed(1, "\n====================\nFile/Dir information\n====================\n")
        report.summarized(1, "StickyBit: Found {} dirs with all users write "
                             "permission and no stickybit\n".format(len(stickydirs)))
        report.detailed(1, "StickyBit: Found {} dirs with all users write permission and "
                           "no stickybit. You should put the sticky bit in order to avoid "
                           "any user can modify files of other users\n".format(len(stickydirs)))
        report.summarized(1, "All users can write: Found {} files with all "
                             "users write permission\n".format(len(alluserwrite)))
        report.detailed(1, "All users can write: Found {} files with all users write "
                           "permission. Is it necessary?\n".format(len(alluserwrite)))
        report.summarized(1, "Read errors: Found {} files or directories with "
                             "errors\n".format(len(readerrors)))
        report.detailed(1, "Read errors: Found {} files or directories with errors. There "
                             "are possible bad links, maybe you want to delete "
                             "them\n".format(len(readerrors)))
        report.summarized(1, "SUID: Found {} files with SUID permission\n".format(len(suidperm)))
        report.detailed(1, "SUID: Found {} files with SUID permission. Are they "
                           "necessary?\n".format(len(suidperm)))
        report.summarized(1, "GUID: Found {} files with GUID permission\n".format(len(guidperm)))
        report.detailed(1, "GUID: Found {} files with GUID permission. Are they "
                           "necessary?\n".format(len(guidperm)))
        for item in stickydirs:
            report.vulns("LOW", "'{}' dir has write permission for "
                                "all user and no sticky bit".format(item))
        for item in alluserwrite:
            report.vulns("LOW", "'{}' file has write permission for all user".format(item))
        for item in readerrors:
            report.vulns("LOW", item)
        for item in suidperm:
            if item[1]:
                report.vulns("MEDIUM", "'{}' file has SUID and "
                                       "it's owned by the root user".format(item[0]))
            else:
                report.vulns("LOW", "'{}' file has SUID. Is it necessary?".format(item[0]))
        for item in guidperm:
            if item[1]:
                report.vulns("MEDIUM", "'{}' file has GUID and "
                                       "it's owned by the root group".format(item[0]))
            else:
                report.vulns("LOW", "'{}' file has GUID. Is it necessary?".format(item[0]))
        report.log("DEBUG", "File and directory permission information completed")
    except Exception as e:
        report.log("ERROR", "Can't obtain file and directory permission information")
        report.log("DEBUG", str(e))
        report.log("DEBUG", traceback.format_exc())
    """
    # Get software reports
    if precheck.checkcommand("dpkg-query"):
        pac2 = _getdpkg()
    elif precheck.checkcommand("apt"):
        pac1 = _getapt()

