from datetime import datetime
from utils import detailfile, detailchapter, reporttitle


class Reporting:

    def __init__(self, filename=None):
        # name of the report
        self.filename = filename

        # store the reports data
        self.summarized_data = [[], [], [], [], [], []]
        self.detailed_data = [[], [], [], [], [], []]
        self.vulns_data = []
        self.infrastructure_data = {}

        # for logging
        self.log_data = []
        self.verbose = 2

        # hardware info
        self.cpuinfo = {}
        self.meminfo = {}
        self.usb = []

        # distro info
        self.oskernel = None
        self.osdistro = None

        # filesystem info
        self.disks = []
        self.mounted = []
        self.unmounted = []
        self.stickydirs = []
        self.alluserwrite = []
        self.readerrors = []
        self.suidperm = []
        self.guidperm = []

        # packages info
        self.packages = []

        # Hostname info
        self.hostname = None
        self.domainname = None
        self.hostid = None
        self.issue = None
        self.issuenet = None
        self.motd = None

        # Users and groups info
        self.users = {}     # Name: [password type, uid, gid, long name, home, shell]
        self.pidusers = {}  # PID: Name
        self.groups = {}

        # Interfaces and route info
        self.ifaces = None
        self.routes = []
        self.iptables = {}
        self.dns = []
        self.ntp = []

        # Services information
        self.runlevel = 0
        self.runningservices = []
        self.failedservices = []
        self.otherservices = []

    def summarized(self, kind, text):
        if kind == 0:
            self.summarized_data[0].append(text)    # Execution environment
        if kind == 1:
            self.summarized_data[1].append(text)    # General information
        if kind == 2:
            self.summarized_data[2].append(text)    # Specific information
        if kind == 3:
            self.summarized_data[3].append(text)    # Volatile information
        if kind == 4:
            self.summarized_data[4].append(text)    # Other information
        if kind == 5:
            self.summarized_data[5].append(text)    # Scan information

    def detailed(self, kind, text):
        if kind == 0:
            self.detailed_data[0].append(text)      # Execution environment
        if kind == 1:
            self.detailed_data[1].append(text)      # General information
        if kind == 2:
            self.detailed_data[2].append(text)      # Specific information
        if kind == 3:
            self.detailed_data[3].append(text)      # Volatile information
        if kind == 4:
            self.detailed_data[4].append(text)      # Other information
        if kind == 5:
            self.detailed_data[5].append(text)      # Scan information

    def vulns(self, severity, text):
        self.vulns_data.append([severity, text])

    def infrastructure(self, ip, hostname):
        if self.infrastructure_data.get(ip):
            if hostname not in self.infrastructure_data[ip]:
                if len(hostname) > 120:
                    self.infrastructure_data[ip].append(hostname[:120]+"...")
                else:
                    self.infrastructure_data[ip].append(hostname)
                return False
        else:
            if len(hostname) > 120:
                self.infrastructure_data[ip] = [hostname[:120]+"..."]
            else:
                self.infrastructure_data[ip] = [hostname]
            return True

    def log(self, severity, text):
        """
        Record a log registry
        :param severity: string DEBUG, INFO, WARNING, ERROR
        :param text: text to log
        """
        date = str(datetime.now())

        if severity == "ERROR" and self.verbose > -1:
            print("ERROR: {}".format(text))
            self.log_data.append([date, severity, text])
        elif severity == "WARNING" and self.verbose > 0:
            self.log_data.append([date, severity, text])
        elif severity == "INFO" and self.verbose > 1:
            self.log_data.append([date, severity, text])
        elif severity == "DEBUG" and self.verbose > 2:
            self.log_data.append([date, severity, text])

    def view_summarized(self, execution=True, general=True,
                        specific=True, volatile=True,
                        other=True, infrastructure=True):
        text = reporttitle("SUMMARIZED INFORMATION")

        if execution:
            text += detailfile("Execution environment")
            for item in self.summarized_data[0]:
                text += item

        if general:
            text += detailfile("General information")
            for item in self.summarized_data[1]:
                text += item

        if specific:
            text += detailfile("Specific information")
            for item in self.summarized_data[2]:
                text += item

        if volatile:
            text += detailfile("Volatile information")
            for item in self.summarized_data[3]:
                text += item

        if other:
            text += detailfile("Other information")
            for item in self.summarized_data[4]:
                text += item

        if infrastructure:
            text += detailfile("Infrastructure information")
            for item in self.summarized_data[5]:
                text += item

        return text

    def view_detailed(self, execution=True, general=True,
                      specific=True, volatile=True,
                      other=True, infrastructure=True):
        text = reporttitle("DETAILED INFORMATION")

        if execution:
            text += detailchapter("EXECUTION ENVIRONMENT")
            for item in self.detailed_data[0]:
                text += item

        if general:
            text += detailchapter("GENERAL INFORMATION")
            for item in self.detailed_data[1]:
                text += item

        if specific:
            text += detailchapter("SPECIFIC INFORMATION")
            for item in self.detailed_data[2]:
                text += item

        if volatile:
            text += detailchapter("VOLATILE INFORMATION")
            for item in self.detailed_data[3]:
                text += item

        if other:
            text += detailchapter("OTHER INFORMATION")
            for item in self.detailed_data[4]:
                text += item

        if infrastructure:
            text += detailchapter("INFRASTRUCTURE INFORMATION")
            for item in self.detailed_data[5]:
                text += item

        return text

    def view_vulns(self):
        text = reporttitle("VULNERABILITIES REPORT")

        self.vulns_data.sort()
        for item in self.vulns_data:
            text += item[0] + " - " + item[1] + "\n"

        return text

    def view_infrastructure(self):
        text = reporttitle("INFRASTRUCTURE REPORT")

        keys = list(self.infrastructure_data.keys())
        keys.sort()
        text += "\nLocal Machine:\n"
        for item in keys:
            if "Local machine" in self.infrastructure_data[item]:
                text += " |__{}\n".format(str(item))
                for name in sorted(self.infrastructure_data[item]):
                    if not "Local machine" in name:
                        text += " |       |__{}\n".format(name)
                del self.infrastructure_data[item]
        text += " o\n"

        keys = list(self.infrastructure_data.keys())
        keys.sort()
        if len(keys) > 0:
            text += "\nRemote IP Address:\n"
            for item in keys:
                text += " |__{}\n".format(str(item))
                for name in sorted(self.infrastructure_data[item]):
                    text += " |       |__{}\n".format(name)
            text += " o\n"

        return text

    def view_all(self, execution=True, general=True,
                 specific=True, volatile=True,
                 other=True, infrastructure=True):
        text = "*******************************\n"
        text += "********* Full report *********\n"
        text += "*******************************\n\n"
        text += self.view_detailed(execution=execution, general=general,
                                   specific=specific, volatile=volatile,
                                   other=other, infrastructure=infrastructure)
        text += self.view_vulns()
        text += self.view_infrastructure()
        text += self.view_summarized(execution=execution, general=general,
                                     specific=specific, volatile=volatile,
                                     other=other, infrastructure=infrastructure)
        return text

    def view_log(self, level="DEBUG"):
        returned_log = ''
        debug = True
        info = True
        warning = True
        error = True

        if level == "INFO":
            debug = False
        elif level == "WARNING":
            debug = False
            info = False
        elif level == "ERROR":
            debug = False
            info = False
            warning = False

        for item in self.log_data:
            if item[1] == "DEBUG" and debug:
                returned_log += item[0] + " - " + item[1] + " - " + item[2] + "\n"
            if item[1] == "INFO" and info:
                returned_log += item[0] + " - " + item[1] + " - " + item[2] + "\n"
            if item[1] == "WARNING" and warning:
                returned_log += item[0] + " - " + item[1] + " - " + item[2] + "\n"
            if item[1] == "ERROR" and error:
                returned_log += item[0] + " - " + item[1] + " - " + item[2] + "\n"

        return returned_log
