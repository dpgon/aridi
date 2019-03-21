from datetime import datetime


class Reporting:

    def __init__(self, filename=None):
        # name of the report
        self.filename = filename

        # store the reports data
        self.summarized_data = [[], [], [], [], [], []]
        self.detailed_data = [[], [], [], [], [], []]
        self.vulns_data = []
        self.infrastructure_data = []

        # for logging
        self.log_data = []
        self.verbose = 2

        # hardware info
        self.cpuinfo = {}
        self.meminfo = {}
        self.usb = []

        # distro info
        self.oskernel = ""
        self.osdistro = ""

        # filesystem info
        self.disks = []
        self.mounted = []
        self.unmounted = []
        self.stickydirs = []
        self.alluserwrite = []
        self.readerrors = []
        self.suidperm = []
        self.guidperm = []

    def summarized(self, kind, text):
        if kind==0:
            self.summarized_data[0].append(text)    # Execution environment
        if kind==1:
            self.summarized_data[1].append(text)    # General information
        if kind==2:
            self.summarized_data[2].append(text)    # Specific information
        if kind==3:
            self.summarized_data[3].append(text)    # Volatile information
        if kind==4:
            self.summarized_data[4].append(text)    # Other information
        if kind==5:
            self.summarized_data[5].append(text)    # Scan information

    def detailed(self, kind, text):
        if kind==0:
            self.detailed_data[0].append(text)      # Execution environment
        if kind==1:
            self.detailed_data[1].append(text)      # General information
        if kind==2:
            self.detailed_data[2].append(text)      # Specific information
        if kind==3:
            self.detailed_data[3].append(text)      # Volatile information
        if kind==4:
            self.detailed_data[4].append(text)      # Other information
        if kind==5:
            self.detailed_data[5].append(text)      # Scan information

    def vulns(self, severity, text):
        self.vulns_data.append([severity, text])

    def infrastructure(self, type, text):
        self.vulns_data.append([type, text])

    def log(self, severity, text):
        """
        Record a log registry
        :param severity: string DEBUG, INFO, WARNING, ERROR
        :param text: text to log
        :return:
        """
        date = str(datetime.now())
        self.log_data.append([date, severity, text])
        if severity == "ERROR" and self.verbose > -1:
            print(date + " - " + severity + " - " + text)
        elif severity == "WARNING" and self.verbose > 0:
            print(date + " - " + severity + " - " + text)
        elif severity == "INFO" and self.verbose > 1:
            print(date + " - " + severity + " - " + text)
        elif severity == "DEBUG" and self.verbose>2:
            print(date + " - " + severity + " - " + text)

    def view_summarized(self, execution=True, general=True,
                        specific=True, volatile=True,
                        other=True, infrastructure=True):
        text = "===============================\n"
        text += "    Summarized information\n"
        text += "===============================\n"

        if execution:
            text += "\nExecution environment\n"
            text += "-------------------------------\n"
            for item in self.summarized_data[0]:
                text += item

        if general:
            text += "\n     General information\n"
            text += "-------------------------------\n"
            for item in self.summarized_data[1]:
                text += item

        if specific:
            text += "\n     Specific information\n"
            text += "-------------------------------\n"
            for item in self.summarized_data[2]:
                text += item

        if volatile:
            text += "\n     Volatile information\n"
            text += "-------------------------------\n"
            for item in self.summarized_data[3]:
                text += item

        if other:
            text += "\n      Other information\n"
            text += "-------------------------------\n"
            for item in self.summarized_data[4]:
                text += item

        if infrastructure:
            text += "\n   Infrastructure information\n"
            text += "-------------------------------\n"
            for item in self.summarized_data[5]:
                text += item

        return text

    def view_detailed(self, execution=True, general=True,
                      specific=True, volatile=True,
                      other=True, infrastructure=True):
        text = "/-----------------------------\\\n"
        text += "|     Detailed information    |\n"
        text += "\-----------------------------/\n\n"

        if execution:
            text += "*******************************\n"
            text += "     Execution environment\n"
            text += "*******************************\n"
            for item in self.detailed_data[0]:
                text += item

        if general:
            text += "*******************************\n"
            text += "      General information\n"
            text += "*******************************\n"
            for item in self.detailed_data[1]:
                text += item

        if specific:
            text += "*******************************\n"
            text += "      Specific information\n"
            text += "*******************************\n"
            for item in self.detailed_data[2]:
                text += item

        if volatile:
            text += "*******************************\n"
            text += "      Volatile information\n"
            text += "*******************************\n"
            for item in self.detailed_data[3]:
                text += item

        if other:
            text += "*******************************\n"
            text += "       Other information\n"
            text += "*******************************\n"
            for item in self.detailed_data[4]:
                text += item

        if infrastructure:
            text += "*******************************\n"
            text += "   Infrastructure information\n"
            text += "*******************************\n"
            for item in self.detailed_data[5]:
                text += item

        return text

    def view_vulns(self):
        text = "===============================\n"
        text += "     Vulnerabilities report\n"
        text += "===============================\n\n"

        self.vulns_data.sort()
        for item in self.vulns_data:
            text += item[0] + " - " + item[1] + "\n"

        return text

    def view_infrastructure(self):
        text = "===============================\n"
        text += "     Infrastructure report\n"
        text += "===============================\n\n"

        self.infrastructure_data.sort()
        for item in self.infrastructure_data:
            text += item[0] + " - " + item[1] + "\n"

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