from os import walk
from ipaddress import ip_address
import traceback, re, socket
from utils import detailheader


def _getetc(report):
    detail = detailheader("/etc information")

    summ = "\n/etc information:\n"

    ipscounter = 0

    detail += "\nIP found:\n"
    for root, dir, file in walk("/etc"):
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
                            if re.match("[#;]", line.split(ips[0])[0]):
                                pass
                            elif "version" in line.split(ips[0])[0].lower():
                                pass
                            else:
                                for data in ips:
                                    detail += " |__{} named in file '{}/{}' " \
                                              "({})\n".format(data, root, item, line.strip())
                                    report.infrastructure(ip_address(data),
                                                          "Named in file '{}/{}' "
                                                          "({})".format(root, item, line.strip()))
                                    ipscounter += 1
                except:
                    pass
                finally:
                    f.close()

    summ += " |__{} ips found in /etc directory\n".format(ipscounter)

    return summ, detail


def getotherinfo(report, precheck):
    # Search in etc directory
    try:
        report.log("DEBUG", "Search in etc directory started")
        summ, detail = _getetc(report)
        report.summarized(4, summ)
        report.detailed(4, detail)
        report.log("DEBUG", "Search in etc directory completed")
    except Exception as e:
        report.log("ERROR", "Can't obtain etc directory information")
        report.log("DEBUG", str(e))
        report.log("DEBUG", traceback.format_exc())