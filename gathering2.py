from traceback import format_exc
from subprocess import check_output, DEVNULL
from socket import gethostname
from ipaddress import ip_address
from utils import detailheader, detailfile, converthex2ip
import re


def _gethostnames(report, precheck):
    summ = '\nHostname and banner info:\n'
    detail = detailheader("Hostnames information")

    if precheck.shouldread('/etc/hostname'):
        report.hostname = open('/etc/hostname').read()
        summ += ' |__hostname: ' + report.hostname
        detail += detailfile('/etc/hostname')
        detail += '{}\n'.format(report.hostname)
    elif precheck.checkcommand("hostname"):
        report.hostname = check_output(["hostname"]).decode("utf-8")
        summ += ' |__hostname: ' + report.hostname
        detail += detailfile('hostname')
        detail += '{}\n'.format(report.hostname)
    else:
        report.hostname = gethostname()
        summ += ' |__hostname: ' + report.hostname
        detail += detailfile('hostname')
        detail += '{}\n'.format(report.hostname)

    if precheck.checkcommand("dnsdomainname"):
        report.domainname = check_output(["dnsdomainname"]).decode("utf-8")
        if report.domainname:
            summ += ' |__dnsdomainname: ' + report.domainname
            detail += detailfile('domainname')
            detail += '{}\n'.format(report.hostname)

    if precheck.checkcommand("hostid"):
        report.hostid = check_output(["hostid"]).decode("utf-8")
        summ += ' |__hostid: ' + report.hostid
        detail += detailfile('hostid')
        detail += '{}\n'.format(report.hostid)

    # Check banner files
    if precheck.shouldread('/etc/issue'):
        report.issue = open('/etc/issue').read()
        summ += ' |__You have an issue banner\n'
        detail += detailfile('/etc/issue')
        detail += '{}\n'.format(report.issue)

    if precheck.shouldread('/etc/issue.net'):
        report.issuenet = open('/etc/issue.net').read()
        summ += ' |__You have an issue.net banner\n'
        detail += detailfile('/etc/issue.net')
        detail += '{}\n'.format(report.issuenet)

    if precheck.shouldread('/etc/motd'):
        report.motd = open('/etc/motd').read()
        summ += ' |__You have an motd banner\n'
        detail += detailfile('/etc/motd')
        detail += '{}\n'.format(report.motd)

    return summ, detail


def _getusers(report, precheck):
    summ = '\nUsers and groups info:\n'
    detail = detailheader("Users and groups")

    # Check users
    if precheck.shouldread('/etc/passwd'):
        output = open('/etc/passwd').readlines()
        for item in output:
            parts = item.strip().split(":")
            report.users[parts[0]] = ["?", parts[2], parts[3], parts[4], parts[5], parts[6], []]
            report.pidusers[int(parts[2])] = parts[0]

    # Check groups
    if precheck.shouldread('/etc/group'):
        output = open('/etc/group').readlines()
        for item in output:
            parts = item.strip().split(":")
            report.groups[parts[0]] = ["?", parts[2], parts[3].split(",")]

    # Check passwords format
    if precheck.shouldread('/etc/shadow'):
        output = open('/etc/shadow').readlines()
        for item in output:
            parts = item.split(":")
            data = report.users.get(parts[0], None)
            if data:
                if parts[1].startswith('$1$'):
                    passwd = "MD5"
                elif parts[1].startswith('$2a$'):
                    passwd = "Blowfish"
                elif parts[1].startswith('$2y$'):
                    passwd = "Blowfish"
                elif parts[1].startswith('$5$'):
                    passwd = "SHA-256"
                elif parts[1].startswith('$6$'):
                    passwd = "SHA-512"
                else:
                    passwd = "No password"
                modify = report.users[parts[0]]
                modify[0] = passwd
                report.users[parts[0]] = modify

    for item in report.groups:
        for user in report.groups[item][2]:
            if user:
                report.users[user][6].append(item)

    summ += " |__Users:"
    line = "\n |    |__"
    upass = 0
    umd5 = 0
    detail += detailfile("Users with any kind of shell or password")
    for item in report.users:
        if report.users[item][0] == "No password" or report.users[item][0] == "?":
            if len(line) > 72:
                summ += line
                line = "\n |    |__"
            else:
                line += "{} ".format(item)
            if "false" not in report.users[item][5] and "nologin" not in report.users[item][5]:
                report.vulns("LOW", "User {0} has shell command {1} and no password. It's "
                                    "recommended to put /bin/false or /sbin/nologin "
                                    "instead {1}.".format(item, report.users[item][5]))
                detail += "\nUser: {}, Home: {}, Shell: {}\n |__Groups: {}\n".\
                    format(item, report.users[item][4], report.users[item][5],
                           report.users[item][6])
        elif report.users[item][0] == "MD5":
            report.vulns("MEDIUM", "User {} has a weak hash algorithm MD5. It's recommended to"
                                   "use a stronger one, like SHA-512".format(item))
            if len(line) > 72:
                summ += line
                line = "\n |    |__"
            else:
                line += "[{}] ".format(item)
            detail += "\nUser: {}, Password: {}, Home: {}, Shell: {}\n |__Groups: {}\n".\
                format(item, report.users[item][0], report.users[item][4], report.users[item][5],
                       report.users[item][6])
            umd5 += 1
            upass += 1
        else:
            if len(line) > 72:
                summ += line
                line = "\n |    |__"
            else:
                line += "[{}] ".format(item)
            detail += "\nUser: {}, Password: {}, Home: {}, Shell: {}\n |__Groups: {}\n".\
                format(item, report.users[item][0], report.users[item][4], report.users[item][5],
                       report.users[item][6])
            upass += 1
    summ += line
    summ += "\n |__Groups:"
    line = "\n |    |__"
    detail += detailfile("Summary of users and groups")
    for item in report.groups:
        if len(line) > 72:
            summ += line
            line = "\n |    |__"
        else:
            line += "{} ".format(item)
    summ += line
    if precheck.root:
        summ += "\n |__There are {} users, {} with password ({} MD5 hashed), " \
                "and {} groups.\n".format(len(report.users), upass, umd5, len(report.groups))
        detail += summ
    else:
        summ += "\n |__There are {} users and {} groups.\n".format(len(report.users),
                                                                   len(report.groups))
        detail += summ

    return summ, detail


def _getnetinfo(report, precheck):
    detail = detailheader("Network information")

    # Check hosts ipv4 in /etc/hosts
    if precheck.shouldread('/etc/hosts'):
        detail += detailfile("/etc/hosts")
        readhost = open('/etc/hosts').readlines()
        for item in readhost:
            item = " ".join(item.split())
            if len(item) > 0:
                if not item.startswith('#') and ":" not in item:
                    ip = ip_address(item.split(" ")[0])
                    detail += "{:>15} - {}\n".format(str(ip), item.split(" ")[1])
                    report.infrastructure(ip, item.split(" ")[1])

    interfaces = {}
    if precheck.checkcommand("ip"):
        # Get interfaces
        output = check_output(["ip", "-o", "link"]).decode("utf-8").splitlines()
        for line in output:
            iface = line.split(":")[1].strip()
            mac = line.split("link")[1].split(" ")[1]
            interfaces[iface] = [mac]

        # Get interfaces address
        output = check_output(["ip", "-o", "address"]).decode("utf-8").splitlines()
        for line in output:
            line = " ".join(line.split()).split(" ")
            if line[2] == "inet":
                interfaces[line[1]] = [interfaces[line[1]][0], line[3]]

    report.ifaces = interfaces

    # Prepare the report for ifaces
    detail += detailfile("Interfaces")
    detail += "          IFACE     MAC ADDRESS     IP ADDRESS/MASK\n"
    summ = '\nNetwork Information:\n'
    for item in interfaces:
        if len(interfaces[item]) > 1:
            detail += "{:>15s}  {:17s}  {}\n".format(item, interfaces[item][0],
                                                     interfaces[item][1])
            summ += " |__Iface {} ({}) with ip address {}.\n".format(item, interfaces[item][0],
                                                                     interfaces[item][1])
            report.infrastructure(ip_address(interfaces[item][1].split("/")[0]), "Local machine")
        else:
            detail += "{:>15s}  {:17s}\n".format(item, interfaces[item][0])
            summ += " |__Iface {} ({}) without ip address.\n".format(item, interfaces[item][0])

    # Get routes
    if precheck.shouldread("/proc/net/route"):
        detail += detailfile("Routes information")

        with open("/proc/net/route") as f:
            info = f.readlines()

        for item in info[1:]:
            item = " ".join(item.split()).split(" ")
            iface = item[0]
            destination = converthex2ip(item[1])
            gateway = converthex2ip(item[2])
            mask = str(bin(int(item[7], 16)))[2:].count("1")
            detail += "Destination: {:>15}/{:0<2} - Gateway: {:15} vía {}\n".format(destination,
                                                                                    mask,
                                                                                    gateway,
                                                                                    iface)
            report.routes.append([destination, mask, gateway, iface])

        detail += detailfile("Other information")

        # Get DNS
        if precheck.shouldread("/etc/resolv.conf"):
            detail += "DNS:\n"

            with open("/etc/resolv.conf") as f:
                info = f.readlines()

            for item in info:
                item = " ".join(item.split()).split(" ")
                if item[0].lower() == "nameserver":
                    detail += " |__{}\n".format(item[1])
                    if len(report.dns) > 0:
                        summ += " |   |__{}\n".format(item[1])
                    else:
                        summ += " |__DNS:\n |   |__{}\n".format(item[1])
                    report.dns.append(item[1])
                    report.infrastructure(precheck.nslookup(item[1]), "DNS Server")
            summ += " o\n"

        # Get NTP
        if precheck.shouldread("/etc/ntp.conf") or precheck.shouldread("/etc/xntp.conf"):
            detail += "NTP:\n"

            if precheck.shouldread("/etc/ntp.conf"):
                with open("/etc/ntp.conf") as f:
                    info = f.readlines()
            else:
                with open("/etc/xntp.conf") as f:
                    info = f.readlines()

            for item in info:
                item = " ".join(item.split()).split(" ")
                if item[0].lower() == "server":
                    detail += " |__SERVER {}\n".format(item[1])
                    if len(report.dns) > 0:
                        summ += " |   |__{}\n".format(item[1])
                    else:
                        summ += " |__NTP:\n |   |__{}\n".format(item[1])
                    report.ntp.append(item[1])
                    report.infrastructure(precheck.nslookup(item[1]), "NTP Server")
                if item[0].lower() == "restrict":
                    detail += " |__CLIENT {}\n".format(item[1])
                    report.infrastructure(precheck.nslookup(item[1]), "NTP Client")
            summ += " o\n"

    return summ, detail


def _getiptables(report, precheck):
    # Root is necesary
    if not precheck.root or not precheck.checkcommand("iptables"):
        return "", ""

    detail = detailheader("IPTables information")
    summ = "\nIPTables information\n"

    output = check_output(["iptables", "-S"]).decode("utf-8").splitlines()

    for item in output:
        if item.startswith("-P"):
            item = " ".join(item.split()).split(" ")
            report.iptables[item[1]] = ["DEFAULT {}".format(item[2])]
        elif item.startswith("-A") and "ACCEPT" in item:
            item = " ".join(item.split()).split(" ")
            if item[1] == "INPUT":
                ip = None
                port = None
                prot = None
                rule = None
                for option in range(len(item)):
                    if item[option] == "-s":
                        ip = item[option+1]
                    elif item[option] == "--dport":
                        port = item[option+1]
                    elif item[option] == "-p":
                        prot = item[option+1]
                    elif item[option] == "-j":
                        rule = item[option+1]
                content = ""
                if port or prot or ip:
                    if rule:
                        content += "{} ".format(rule)
                    if ip:
                        content += ip
                        if re.fullmatch("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/32", ip) \
                                and rule == "ACCEPT":
                            ip = ip_address(ip[:-3])
                            report.infrastructure(ip, "IPTables allowed input IP")
                            if port and prot:
                                report.infrastructure(ip, "Consumer in port {} ({})".format(port,
                                                                                            prot))
                            elif port:
                                report.infrastructure(ip, "Consumer in port {}".format(port))
                            elif prot:
                                report.infrastructure(ip, "Consumer only protocol {}".format(prot))
                    if port:
                        content += ":{}".format(port)
                    if prot:
                        content += "({})".format(prot)
                    report.iptables["INPUT"].append(content)

            elif item[1] == "OUTPUT":
                ip = None
                port = None
                prot = None
                rule = None
                for option in range(len(item)):
                    if item[option] == "-d":
                        ip = item[option+1]
                    elif item[option] == "--dport":
                        port = item[option+1]
                    elif item[option] == "-p":
                        prot = item[option+1]
                    elif item[option] == "-j":
                        rule = item[option+1]
                content = ""
                if port or prot or ip:
                    if rule:
                        content += "{} ".format(rule)
                    if ip:
                        content += ip
                        if re.fullmatch("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/32", ip) \
                                and rule == "ACCEPT":
                            ip = ip_address(ip[:-3])
                            report.infrastructure(ip, "IPTables allowed output IP")
                            if port and prot:
                                report.infrastructure(ip, "Service in port {} ({})".format(port,
                                                                                           prot))
                            elif port:
                                report.infrastructure(ip, "Service in port {}".format(port))
                            elif prot:
                                report.infrastructure(ip, "Service only protocol {}".format(prot))
                    if port:
                        content += ":{}".format(port)
                    if prot:
                        content += "({})".format(prot)
                    report.iptables["OUTPUT"].append(content)

    if report.iptables["INPUT"]:
        detail += "\nINPUT:\n"
        summ += " |__INPUT:\n"
        for item in report.iptables["INPUT"]:
            detail += " |__{}\n".format(item)
            summ += " |   |__{}\n".format(item)

    if report.iptables["FORWARD"]:
        detail += "\nFORWARD:\n"
        summ += " |__FORWARD:\n"
        for item in report.iptables["FORWARD"]:
            detail += " |__{}\n".format(item)
            summ += " |   |__{}\n".format(item)
    if report.iptables["OUTPUT"]:
        detail += "\nOUTPUT:\n"
        summ += " |__OUTPUT:\n"
        for item in report.iptables["OUTPUT"]:
            detail += " |__{}\n".format(item)
            summ += "     |__{}\n".format(item)

    return summ, detail


def _getrunningservices(precheck, report):
    detail = detailheader("Services information")
    summ = ""

    if precheck.checkcommand("runlevel"):
        try:
            message = None
            output = check_output(["runlevel"], stderr=DEVNULL).decode("utf-8").split(" ")
            report.runlevel = int(output[1])
            if report.runlevel == 1:
                message = "Runlevel 1: Single-user mode"
            elif report.runlevel == 2:
                message = "Runlevel 2: Multi-user mode"
            elif report.runlevel == 3:
                message = "Runlevel 3: Multi-user mode with networking"
            elif report.runlevel == 4:
                message = "Runlevel 4: Not used/user-definable"
            elif report.runlevel == 5:
                message = "Runlevel 5: Start the system normally with appropriate display manager"
            if message:
                detail += "{:^80}\n".format(message)
                summ += "\n{}\n |__{}\n".format(message.split(":")[0], message.split(":")[1])
        except Exception as e:
            report.log("INFO", "Unknown runlevel")
            report.log("DEBUG", str(e))

    if precheck.checkcommand("systemctl"):
        output = check_output(["systemctl", "list-units"]).decode("utf-8").splitlines()
        detail += detailfile("systemd services:")
        summ += "\nSystemd services:\n"
        for item in output:
            if "   loaded" in item:
                item = " ".join(item.split()).split(" ")
                if len(item[0]) > 1:
                    unit = item[0]
                    sub = item[3]
                    description = " ".join(item[4:])
                else:
                    unit = item[1]
                    sub = item[4]
                    description = " ".join(item[5:])
                if sub == "running":
                    report.runningservices.append([unit, description])
                elif sub == "failed":
                    report.failedservices.append([unit, description])
                # Ignore mount and plugged
                elif sub == "waiting" or sub == "exited" or sub == "active" \
                        or sub == "listening" or sub == "elapsed":
                    report.otherservices.append([sub, unit, description])

    elif precheck.checkcommand("chkconfig"):
        output = check_output(["chkconfig", "--list"]).decode("utf-8").splitlines()
        detail += detailfile("SysV init services:")
        summ += "\nSysV init enabled services:\n"
        if 0 < report.runlevel < 6:
            checkon = "{}:on".format(report.runlevel)
            checkoff = "{}:off".format(report.runlevel)
            for item in output:
                item = " ".join(item.split())
                if checkon in item:
                    report.runningservices.append([item.split(" ")[0], ""])
                elif checkoff in item:
                    report.otherservices.append(["stopped", item.split(" ")[0], ""])

    report.runningservices.sort()
    report.failedservices.sort()
    report.otherservices.sort()

    if report.failedservices:
        detail += "\nFailed services:\n"
        summ += " |__Failed services:\n"
        for item in report.failedservices:
            if len(item[1]) > 0:
                detail += " |__{} ({})\n".format(item[0], item[1])
                summ += " |    |__{} ({})\n".format(item[0], item[1])
                report.vulns("LOW", "Service {} ({}) has failed.".format(item[0], item[1]))
            else:
                detail += " |__{}\n".format(item[0])
                summ += " |    |__{}\n".format(item[0])
                report.vulns("LOW", "Service {} has failed.".format(item[0]))

    if report.runningservices:
        detail += "\nRunning services:\n"
        summ += " |__Running services: {}\n".format(len(report.runningservices))
        for item in report.runningservices:
            if len(item[1]) > 0:
                detail += " |__{} ({})\n".format(item[0], item[1])
            else:
                detail += " |__{}\n".format(item[0])

    if report.otherservices:
        detail += "\nOther state:\n"
        summ += " |__Other state services: {}\n".format(len(report.otherservices))
        state = ""
        for item in report.otherservices:
            if len(item[2]) > 0:
                if item[0] == state:
                    detail += " |     |__{} ({})\n".format(item[1], item[2])
                else:
                    state = item[0]
                    detail += " |__{}\n |     |__{} ({})\n".format(item[0], item[1], item[2])
            else:
                if item[0] == state:
                    detail += " |     |__{}\n".format(item[1])
                else:
                    state = item[0]
                    detail += " |__{}\n |     |__{}\n".format(item[0], item[1])

    return summ, detail


def getspecificinfo(report, precheck):
    # Get host information
    try:
        report.log("DEBUG", "Host names information gathering started")
        summ, detail = _gethostnames(report, precheck)
        report.summarized(2, summ)
        report.detailed(2, detail)
        report.log("DEBUG", "Host names information completed")
    except Exception as e:
        report.log("ERROR", "Can't obtain Host names information")
        report.log("DEBUG", str(e))
        report.log("DEBUG", format_exc())

    # Get users, groups and sudoers information
    try:
        report.log("DEBUG", "Users and groups information gathering started")
        summ, detail = _getusers(report, precheck)
        report.summarized(2, summ)
        report.detailed(2, detail)
        report.log("DEBUG", "Users and groups information completed")
    except Exception as e:
        report.log("ERROR", "Can't obtain users and groups information")
        report.log("DEBUG", str(e))
        report.log("DEBUG", format_exc())

    # Get services information
    try:
        report.log("DEBUG", "Services information gathering started")
        summ, detail = _getrunningservices(precheck, report)
        report.summarized(2, summ)
        report.detailed(2, detail)
        report.log("DEBUG", "Services information completed")
    except Exception as e:
        report.log("ERROR", "Can't obtain Services information")
        report.log("DEBUG", str(e))
        report.log("DEBUG", format_exc())

    # Get network information
    try:
        report.log("DEBUG", "Network information gathering started")
        summ, detail = _getnetinfo(report, precheck)
        report.summarized(2, summ)
        report.detailed(2, detail)
        report.log("DEBUG", "Network information completed")
    except Exception as e:
        report.log("ERROR", "Can't obtain network information")
        report.log("DEBUG", str(e))
        report.log("DEBUG", format_exc())

    # Get iptables information
    try:
        report.log("DEBUG", "IPTables information gathering started")
        summ, detail = _getiptables(report, precheck)
        report.summarized(2, summ)
        report.detailed(2, detail)
        report.log("DEBUG", "IPTables information completed")
    except Exception as e:
        report.log("ERROR", "Can't obtain IPTables information")
        report.log("DEBUG", str(e))
        report.log("DEBUG", format_exc())
