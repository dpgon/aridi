import socket, threading, traceback
from struct import pack, unpack
from binascii import hexlify, unhexlify
from ipaddress import ip_address, ip_network
from time import sleep
from gathering2 import _getnetinfo
from utils import detailheader, percentagebar

waiting = True
ipmac = {}
ports = []


def _scanans(iface):
    global waiting
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))

    while waiting:
        packet = s.recvfrom(2048)

        ethernet_header = packet[0][0:14]
        ethernet_detailed = unpack("!6s6s2s", ethernet_header)

        arp_header = packet[0][14:42]
        arp_detailed = unpack("2s2s1s1s2s6s4s6s4s", arp_header)

        # only listen to ARP packets
        ethertype = ethernet_detailed[2]
        if ethertype == b'\x08\x06':
            sourcemac = hexlify(arp_detailed[5]).decode('utf-8').upper()
            destmac = hexlify(arp_detailed[7]).decode('utf-8').upper()
            sourceip = ip_address(arp_detailed[6])
            destip = ip_address(arp_detailed[8])

            if sourcemac != "000000000000" and sourcemac != "FFFFFFFFFFFF":
                if sourceip not in ipmac:
                    ipmac[sourceip] = sourcemac

            if destmac != "000000000000" and destmac != "FFFFFFFFFFFF":
                if destip not in ipmac:
                    ipmac[destip] = destmac


def _arppacket(destip, sourceip, sourcemac, iface):
    sourcemac = unhexlify(sourcemac.replace(':', ''))
    broadmac = b'\xFF\xFF\xFF\xFF\xFF\xFF'

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    s.bind((iface, socket.htons(3)))

    # Ethernet Header
    protocol = 0x0806   # 0x0806 for ARP
    eth_hdr = pack("!6s6sH", broadmac, sourcemac, protocol)

    # ARP header
    htype = 0x0001      # Hardware type ethernet
    ptype = 0x0800      # Protocol type TCP
    hlen = 0x06         # Hardware address Len
    plen = 0x04         # Protocol addr. len
    operation = 0x0001  # 1=request/2=reply
    src_ip = socket.inet_aton(sourceip)
    dst_ip = socket.inet_aton(destip)
    arp_hdr = pack("!HHBBH6s4s6s4s", htype, ptype, hlen, plen,
                   operation, sourcemac, src_ip, broadmac, dst_ip)

    packet = eth_hdr + arp_hdr

    s.send(packet)


def _localnetworkarpscan(iface, sourcemac, network):
    global waiting

    sourceip = network.split("/")[0]
    network = ip_network(network, strict=False)

    threads = []

    ans = threading.Thread(target=_scanans, args=(iface, ))

    for i in network:
        t = threading.Thread(target=_arppacket, args=(str(i), sourceip, sourcemac, iface))
        threads.append(t)

    ans.start()

    for item in threads:
        item.start()

    # when all packets are out, it should has only 2 threads, the main and scanans()
    while threading.active_count() > 2:
        pass

    # Wait 5 seconds an answer
    sleep(5)

    waiting = False

    while threading.active_count() > 1:
        pass

    waiting = True


def _opentcpport(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.settimeout(1)

    try:
        s.connect((str(ip), port))
        ports.append(port)
    except:
        return None


def _ipscan(ip, precheck):
    global ports
    ports = []
    threads = []

    for port in precheck.portnames:
        t = threading.Thread(target=_opentcpport, args=(ip, port))
        threads.append(t)

    for item in threads:
        item.start()

    while threading.active_count() > 1:
        pass

    return ports


def _portscan(report, precheck):
    detail = detailheader("Port scan")
    summ = "\nPort scan:\n"

    summ += " |__Total IPs in infrastructure: {}\n".format(len(report.infrastructure_data))
    detail += "\nTotal IPs in infrastructure: {}\n".format(len(report.infrastructure_data))

    localmachine = []
    localnetwork = []
    outconns = []
    inconns = []
    carvips = []
    carvfqdn = []
    for item in sorted(report.infrastructure_data):
        if "Local machine" in report.infrastructure_data[item]:
            localmachine.append(item)
        elif [x for x in report.infrastructure_data[item] if x.startswith("Connected at")]:
            outconns.append(item)
        elif [x for x in report.infrastructure_data[item] if x.startswith("Connected in")]:
            inconns.append(item)
        elif [x for x in report.infrastructure_data[item] if x.startswith("MAC")]:
            localnetwork.append(item)
        elif [x for x in report.infrastructure_data[item] if x.startswith("Named")]:
            carvips.append(item)
        elif [x for x in report.infrastructure_data[item] if x.startswith("Found")]:
            carvfqdn.append(item)

    print("\n(a) TOTAL IPs: {:>10}\n(m) Local machine IPs: {:>5}\n(n) Local network IPs: {:>5}\n"
          "(o) Outgoing connections: {:>3}\n(i) Incoming connections: {:>3}\n(x) Carved IPs: {:>9}"
          "\n(y)Carved FQDN: {:>8}".format(len(report.infrastructure_data), len(localmachine),
                                        len(localnetwork), len(outconns), len(inconns),
                                        len(carvips), len(carvfqdn)))

    print("What kind of IPs do you want to scan (write one or several letters): ", end="")
    ans = str(input()).lower().lstrip()
    scanlist = []
    if 'a' in ans:
        scanlist = sorted(report.infrastructure_data)
    else:
        if 'm' in ans:
            scanlist += localmachine
        if 'n' in ans:
            scanlist += localnetwork
        if 'o' in ans:
            scanlist += outconns
        if 'i' in ans:
            scanlist += inconns
        if 'x' in ans:
            scanlist += carvips
        if 'y' in ans:
            scanlist += carvfqdn

    summ += " |__Total IPs to scan: {}\n".format(len(scanlist))
    detail += "\nTotal IPs to scan: {}\n".format(len(scanlist))

    portcounter = 0
    total = len(scanlist)
    for idx, item in enumerate(scanlist):
        percentagebar(total, idx)
        detail += "\n{}\n".format(item)
        result = _ipscan(item, precheck)
        for port in result:
            detail += " |__{:5} - {}\n".format(port, precheck.portnames[port][1])
            report.infrastructure(item, "Port TCP {} open ({})".format(port,
                                                                       precheck.portnames[port][1]))
            portcounter += 1
    percentagebar(total, total)
    summ += " |__{} open ports found\n".format(portcounter)

    return summ, detail


def scaninfrastructure(report, precheck, mask):
    # arp scan of local network
    if precheck.root:
        try:
            report.log("DEBUG", "Scan local networks started")

            if not report.ifaces:
                _getnetinfo(report, precheck)

            totalip = 0
            for iface in report.ifaces:
                if len(report.ifaces[iface]) > 1 and iface != "lo" and \
                        int(report.ifaces[iface][1].split("/")[1]) >= mask:
                    totalip += pow(2, 32 - int(report.ifaces[iface][1].split("/")[1]))

            print("\nThere are {} possible ips in all subnets to scan with a /{} "
                  "mask or smaller. It could take some time. Do you want to "
                  "continue with ? (y/N) ".format(totalip, mask), end="")
            ans = str(input()).lower().lstrip()

            if len(ans) > 0 and 'y' in ans[0]:
                summ = "\nARP scan:\n"
                detailed = detailheader("ARP Scan")

                counter = 0
                total = len(report.ifaces)
                for iface in report.ifaces:
                    percentagebar(total, counter)
                    if len(report.ifaces[iface]) > 1 and iface != "lo" and \
                            int(report.ifaces[iface][1].split("/")[1]) > 22:

                        _localnetworkarpscan(iface, report.ifaces[iface][0],
                                             report.ifaces[iface][1])
                    counter += 1
                percentagebar(total, counter)

                for item in sorted(ipmac):
                    summ += "  |__IP: {:16} [{}]\n".format(str(item), ipmac[item])
                    if report.infrastructure(ip_address(item), "MAC {}".format(ipmac[item])):
                        detailed += " IP: {:16}   MAC: {}\n".format(str(item), ipmac[item])

                report.summarized(5, summ)
                report.detailed(5, detailed)

            report.log("DEBUG", "Scan local networks completed")
        except Exception as e:
            report.log("ERROR", "Can't finish local networks scan")
            report.log("DEBUG", str(e))
            report.log("DEBUG", traceback.format_exc())
    else:
        report.log("INFO", "You don't have root permission to scan local networks")

    # Scan ports
    try:
        report.log("DEBUG", "Port scan started")
        summ, detail = _portscan(report, precheck)
        report.summarized(5, summ)
        report.detailed(5, detail)
        report.log("DEBUG", "Port scan completed")
    except Exception as e:
        report.log("ERROR", "Can't scan ports")
        report.log("DEBUG", str(e))
        report.log("DEBUG", traceback.format_exc())