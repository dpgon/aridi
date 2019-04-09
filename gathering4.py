import traceback
import re
import socket
from os import walk, listdir
from os.path import isdir
from ipaddress import ip_address
from utils import detailheader, percentagebar


def _getetc(report):
    detail = detailheader("/etc information")

    summ = "\n/etc information:\n"

    # Percentage calculate
    dirs = ['/etc/' + x for x in listdir("/etc") if isdir("/etc/" + x)]
    total = len(dirs)

    ipscounter = 0

    detail += "\nIP found:\n"
    for root, dir, file in walk("/etc"):
        if root in dirs:
            dirs.remove(root)
            percentagebar(total, total-len(dirs))

        for item in file:
            if not "dhcpd" in item:
                try:
                    f = open(root + "/" + item, "r")
                    content = f.readlines()
                    for line in content:
                        ips = re.findall("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", line)

                        ips2 = ips.copy()
                        for data in ips2:
                            try:
                                socket.inet_aton(data)
                                if data.startswith("169.254"):
                                    ips.remove(data)
                                elif int(data.split(".")[0]) > 223 or int(data.split(".")[0]) == 0:
                                    ips.remove(data)
                                elif int(data.split(".")[3]) == 0:
                                    ips.remove(data)
                                elif line.split(data)[1].startswith("/") and \
                                        not line.split(data)[1].startswith("/32"):
                                    ips.remove(data)
                                elif re.match("[\d.]", line.split(data)[1][0]):
                                    ips.remove(data)
                                elif len(line.split(data)[0]) > 0:
                                    if re.match("[\d.]", line.split(data)[0][-1]):
                                        ips.remove(data)
                            except socket.error:
                                ips.remove(data)

                        if ips:
                            if not re.match("[#;]", line.split(ips[0])[0]) and \
                                    not "version" in line.split(ips[0])[0].lower():
                                line = " ".join(line.strip().split())
                                for data in ips:
                                    detail += " |__{} named in file '{}/{}'\n".format(data, root,
                                                                                    item)
                                    report.infrastructure(ip_address(data),
                                                          "Named in file '{}/{}' "
                                                          "({})".format(root, item, line))
                                    ipscounter += 1
                except:
                    pass
                finally:
                    f.close()
    percentagebar(total, total)

    summ += " |__{} ips found in /etc directory\n".format(ipscounter)

    return summ, detail


def _getetcfqdn(precheck, report):
    fqdn = {}

    for root, dir, file in walk("/etc"):
        for item in file:
            try:
                f = open(root + "/" + item, "r")
                content = f.readlines()
                for line in content:
                    if not re.match("[#;<]", line.strip()):
                        line = " ".join(line.strip().split())
                        for part in line.split():
                            if not "@" in part:
                                names = re.findall("[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63})+"
                                                   "\.[a-z0-9-]{1,63}", part)
                                if names:
                                    for name in names:
                                        if re.search("\D", name.replace(".", "")) and not name in fqdn:
                                            fqdn[name] = ["{}/{}".format(root, item), line]
            except:
                pass
            finally:
                f.close()

    total = len(fqdn)
    print("\nThere are {} possible FQDN in /etc. It's possible to do a DNS query "
          "in order to detect real FQDN, but it could take some time. Do you want"
          " to continue with ? (y/N) ".format(total), end="")

    ans = str(input()).lower().lstrip()
    if len(ans) > 0 and 'y' in ans[0]:
        detail = "\nFQDN found:\n"
        ipcounter = 0

        for idx, item in enumerate(fqdn):
            ipaddr = precheck.nslookup(item)
            percentagebar(total, idx)
            if ipaddr:
                ipcounter += 1
                report.infrastructure(ipaddr, "FQDN {}".format(item))
                report.infrastructure(ipaddr, "Found in file {}: {}".format(fqdn[item][0],
                                                                            fqdn[item][1]))
                detail += " |__{} ({})\n".format(item, ipaddr)
        percentagebar(total, total)

        summ = " |__{} FQDN found\n".format(ipcounter)
    else:
        summ = ""
        detail = ""

    return summ, detail


def _getlog(report):
    detail = detailheader("/var/log information")

    summ = "\n/var/log information:\n"

    # Percentage calculate
    dirs = ['/var/log/' + x for x in listdir("/var/log") if isdir("/var/log/" + x)]
    total = len(dirs)

    ipscounter = 0

    detail += "\nIP found:\n"
    for root, dir, file in walk("/var/log"):
        if root in dirs:
            dirs.remove(root)
            percentagebar(total, total-len(dirs))

        for item in file:
            ipdetected = []
            try:
                f = open(root + "/" + item, "r")
                content = f.readlines()
                f.close()
                for line in content:
                    ips = re.findall("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", line)

                    ips2 = ips.copy()
                    for data in ips2:
                        try:
                            socket.inet_aton(data)
                            if data.startswith("169.254"):
                                ips.remove(data)
                            elif int(data.split(".")[0]) > 223 or int(data.split(".")[0]) == 0:
                                ips.remove(data)
                            elif int(data.split(".")[3]) == 0:
                                ips.remove(data)
                            elif line.split(data)[1].startswith("/") and \
                                    not line.split(data)[1].startswith("/32"):
                                ips.remove(data)
                            elif re.match("[\d.]", line.split(data)[1][0]):
                                ips.remove(data)
                            elif len(line.split(data)[0]) > 0:
                                if re.match("[\d.]", line.split(data)[0][-1]):
                                    ips.remove(data)
                        except socket.error:
                            ips.remove(data)

                    if ips:
                        if "version" not in line.split(ips[0])[0].lower() and \
                                line.split(ips[0])[1][0] != "-":
                            line = " ".join(line.strip().split())
                            for data in ips:
                                if data not in ipdetected:
                                    ipdetected.append(data)
                                    detail += " |__{} named in file '{}/{}'\n".format(data, root,
                                                                                      item)
                                    report.infrastructure(ip_address(data),
                                                          "Named in file '{}/{}' "
                                                          "({})".format(root, item, line))
                                    ipscounter += 1
            except:
                pass
    percentagebar(total, total)

    summ += " |__{} ips found in /var/log directory\n".format(ipscounter)

    return summ, detail


def _getlogfqdn(precheck, report):
    fqdn = {}

    for root, dir, file in walk("/var/log"):
        for item in file:
            try:
                f = open(root + "/" + item, "r")
                content = f.readlines()
                f.close()
                for line in content:
                    if not re.match("[#;<]", line.strip()) and \
                            "version" not in line.lower() and \
                            "initrd" not in line.lower() and \
                            "vmlinuz" not in line.lower():
                        line = " ".join(line.strip().split())
                        for part in line.split():
                            if not "@" in part:
                                names = re.findall("[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63})+"
                                                   "\.[a-z0-9-]{1,63}", part)
                                if names:
                                    for name in names:
                                        if re.search("\D{3}", name.replace(".", "").replace("-", ""))\
                                                and name not in fqdn:
                                            fqdn[name] = ["{}/{}".format(root, item), line]
            except:
                pass

    total = len(fqdn)
    print("\nThere are {} possible FQDN in /var/log. It's possible to do a DNS query "
          "in order to detect real FQDN, but it could take some time. Do you want"
          " to continue with ? (y/N) ".format(total), end="")
    ans = str(input()).lower().lstrip()
    if len(ans) > 0 and 'y' in ans[0]:
        detail = "\nFQDN found:\n"
        ipcounter = 0

        for idx, item in enumerate(fqdn):
            ipaddr = precheck.nslookup(item)
            percentagebar(total, idx)
            if ipaddr:
                ipcounter += 1
                report.infrastructure(ipaddr, "FQDN {}".format(item))
                report.infrastructure(ipaddr, "Found in file {}: {}".format(fqdn[item][0],
                                                                            fqdn[item][1]))
                detail += " |__{} ({})\n".format(item, ipaddr)
        percentagebar(total, total)

        summ = " |__{} FQDN found\n".format(ipcounter)
    else:
        summ = ""
        detail = ""

    return summ, detail


def getotherinfo(report, precheck):
    # Search in etc directory
    try:
        report.log("DEBUG", "Search in /etc directory started")
        summ, detail = _getetc(report)
        report.summarized(4, summ)
        report.detailed(4, detail)
        summ, detail = _getetcfqdn(precheck, report)
        report.summarized(4, summ)
        report.detailed(4, detail)
        report.log("DEBUG", "Search in /etc directory completed")
    except Exception as e:
        report.log("ERROR", "Can't obtain /etc directory information")
        report.log("DEBUG", str(e))
        report.log("DEBUG", traceback.format_exc())

    # Search in etc directory
    try:
        report.log("DEBUG", "Search in /var/log directory started")
        summ, detail = _getlog(report)
        report.summarized(4, summ)
        report.detailed(4, detail)
        summ, detail = _getlogfqdn(precheck, report)
        report.summarized(4, summ)
        report.detailed(4, detail)
        report.log("DEBUG", "Search in /var/log directory completed")
    except Exception as e:
        report.log("ERROR", "Can't obtain /var/log directory information")
        report.log("DEBUG", str(e))
        report.log("DEBUG", traceback.format_exc())
