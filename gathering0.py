import os, re
from os.path import isfile
from subprocess import check_output, DEVNULL, CalledProcessError
from ipaddress import ip_address


class Precheck:

    portnames = {}

    interesting_files = [["/etc/environment", 0],       # Path info in precheck stage
                         ["/proc/cpuinfo", 1],          # Hardware info
                         ["/proc/meminfo", 1],
                         ["/etc/os-release", 2],        # Distro info
                         ["/etc/lsb-release", 2],
                         ["/suse/etc/SuSE-release", 2],
                         ["/etc/redhat-release", 2],
                         ["/etc/centos-release", 2],
                         ["/etc/fedora-release", 2],
                         ["/etc/debian-version", 2],
                         ["/etc/slackware-version", 2],
                         ["/proc/swaps", 3],             # Filesystem info
                         ["/etc/apt/sources.list", 4],  # Software info
                         ["/etc/hostname", 5],
                         ["/etc/hosts", 5],
                         ["/etc/issue", 5],
                         ["/etc/issue.net", 5],
                         ["/etc/motd", 5],
                         ["/etc/passwd", 6],            # Users config
                         ["/etc/group", 6],
                         ["/etc/shadow", 6],
                         ["/etc/gshadow", 6],
                         ["/etc/sudoers", 6],
                         ["/proc/net/route", 7],        # Network config
                         ["/etc/hosts", 7],
                         ["/etc/hosts.allow", 7],
                         ["/etc/hosts.deny", 7],
                         ["/etc/resolv.conf", 7],
                         ["/etc/sysctl.conf", 8],       # Security information
                         ["/etc/security/access.conf", 8],
                         ["/etc/pam.conf", 8],
                         ["/etc/pam.d/passwd", 8],
                         ["/etc/systemd/user.conf", 9], # Services information
                         ["/etc/systemd/system.conf", 9],
                         ["/etc/ssh/sshd_config", 10],  # Other services information
                         ["/var/log/wtmp", 12],         # Users login information
                         ["/var/log/btmp", 12],
                         ["/var/log/utmp", 12],
                         ["/var/run/utmp", 12],
                         ["/run/utmp", 12],
                         ["/proc/diskstats", 13],       # Disk stats
                         ["/proc/sys/fs/file-nr", 13],
                         ["/proc/sys/fs/inode-nr", 13],
                         ["/proc/loadavg", 15],         # CPU stats
                         ["/proc/stat", 15],
                         ["/proc/net/tcp", 16],         # Network connections
                         ["/proc/net/udp", 16],
                         ["/var/log/message", 18],      # Estudio de Logs
                         ["/var/log/auth.log", 18],
                         ["/var/log/utmp", 18],
                         ["/var/log/btmp", 18],
                         ["/var/log/kern.log", 18],
                         ["/var/log/cron.log", 18],
                         ["/var/log/maillog", 18],
                         ["/var/log/boot.log", 18],
                         ["/var/log/mysqld.log", 18],
                         ["/var/log/secure", 18],
                         ["/var/log/yum.log", 18],
                         ["/var/log/dpkg.log", 18],
                         ["/var/log/syslog", 18]]

    def __init__(self):
        self.uid = os.getuid()
        self.gid = os.getgid()
        self.gids = os.getgroups()
        self.root = self.amiroot()
        self.files = {}
        self._examinefiles()

    @staticmethod
    def loadports(file):
        try:
            if isfile(file):
                with open(file, "r") as f:
                    portlist = f.readlines()
                for item in portlist:
                    item = item.strip().split("|")
                    if not item[1] in Precheck.portnames.keys():
                        if len(item) > 2:
                            Precheck.portnames[int(item[1])] = [item[0], item[2]]
                        else:
                            Precheck.portnames[int(item[1])] = [item[0], ""]
                return True
            else:
                return False
        except:
            return False

    @staticmethod
    def checkcommand(command):
        # Check if command is available in current dir
        if isfile(command):
            return os.getcwd()+"/"+command

        # Check if command is available in path
        path = os.environ["PATH"].split(':')
        for item in path:
            if isfile(item + "/" + command):
                return item + "/" + command

        # Return None if command not found
        return None

    @staticmethod
    def canread(filename, uid, gids):
        if not isfile(filename):
            return -1
        info = os.stat(filename)
        owner = info.st_uid
        group = info.st_gid
        if info.st_mode & 0b000000100:
            return 3
        elif info.st_mode & 0b000100000 and group in gids:
            return 2
        elif owner == uid:
            return 1
        else:
            return 0

    @staticmethod
    def nslookup(hostname):
        if re.fullmatch("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", hostname):
            return ip_address(hostname)

        if Precheck.checkcommand("nslookup"):
            ip = None
            try:
                output = check_output(["nslookup", hostname],
                                      stderr=DEVNULL).decode("utf-8").splitlines()
                for line in output:
                    line = " ".join(line.split()).split(" ")
                    try:
                        if line[0].startswith("Address") and \
                                re.fullmatch("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", line[1]):
                            ip = ip_address(line[1])
                    except:
                        pass
            except CalledProcessError as e:
                ip = None
            return ip

        if Precheck.checkcommand("dig"):
            ip = None
            try:
                output = check_output(["dig", hostname],
                                      stderr=DEVNULL).decode("utf-8").splitlines()
                for line in output:
                    line = " ".join(line.split()).split(" ")
                    try:
                        if line[0].startswith(hostname):
                            if line[-2] == "A" and \
                                    re.fullmatch("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", line[-1]):
                                ip = ip_address(line[-1])
                            elif line[-2] == "CNAME":
                                ip = Precheck.nslookup(line[-1])
                    except:
                        pass
            except CalledProcessError as e:
                ip = None
            return ip

    def amiroot(self):
        if self.uid == 0:
            return True
        else:
            return False

    def _examinefiles(self):
        for item in self.interesting_files:
            if isfile(item[0]):
                perm = str(oct(os.stat(item[0]).st_mode))[-3:]
            else:
                perm = 0
            self.files[item[0]] = [item[1], self.canread(item[0], self.uid, self.gids), perm]

    def shouldread(self, filename):
        if self.files.get(filename, [0, 0])[1] > 0:
            return True
        else:
            return False

    def _perm(self, filename, recommended):
        actual = self.files.get(filename)[2]
        if actual != recommended or actual == 0:
            return "Permission of {} is {}, but it's recommended {}".format(filename,
                                                                            actual,
                                                                            recommended)
        else:
            return None

    def dangerousperm(self):
        vulns = [self._perm("/etc/passwd", "644"),
                 self._perm("/etc/group", "644"),
                 self._perm("/etc/shadow", "400"),
                 self._perm("/etc/gshadow", "400")]

        return list(filter(lambda value: value, vulns))
