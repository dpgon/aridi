"""TCP connect scanner of the central (TODO.md 7.3). Standard library only.

Never touches an address outside an active AuthorizedNetwork: the targets are the hosts
of one authorized network, and before every connection the address is checked again
against the active networks (Perimeter), so deactivating a network stops its scan.
Addresses that only appear in relations (logs, carving) are never targets.
"""

import logging
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor

log = logging.getLogger(__name__)

# The most common TCP ports (services of servers and network equipment).
COMMON_PORTS = (
    20, 21, 22, 23, 25, 53, 69, 80, 81, 88, 110, 111, 119, 123, 135, 137, 139, 143, 161,
    179, 389, 427, 443, 444, 445, 465, 500, 512, 513, 514, 515, 548, 554, 587, 623, 631,
    636, 873, 902, 990, 993, 995, 1025, 1080, 1194, 1433, 1521, 1723, 1883, 2049, 2082,
    2083, 2181, 2375, 2376, 2379, 3000, 3128, 3268, 3306, 3389, 3690, 4369, 4443, 5000,
    5060, 5432, 5601, 5672, 5900, 5985, 5986, 6000, 6379, 6443, 6667, 7001, 8000, 8008,
    8080, 8081, 8086, 8088, 8443, 8888, 9000, 9090, 9092, 9100, 9200, 9300, 9418, 10000,
    10250, 11211, 15672, 27017, 50000,
)
ALL_PORTS = tuple(range(1, 65536))


class OutsidePerimeter(Exception):
    """A connection to an address outside every active authorized network was refused."""


class Perimeter:
    """The active authorized networks. The scanning thread reloads them every REFRESH
    seconds (refresh()); the probing threads only read the last list (contains())."""

    REFRESH = 5.0

    def __init__(self, load):
        self.load = load          # () -> [ip_network]
        self.networks, self.loaded = (), None
        self.refresh()

    def refresh(self, force=True):
        now = time.monotonic()
        if force or self.loaded is None or now - self.loaded >= self.REFRESH:
            self.networks, self.loaded = tuple(self.load()), now

    def contains(self, ip):
        return any(ip.version == net.version and ip in net for net in self.networks)


class RateLimit:
    """At most RATE connection attempts per second, shared by every thread."""

    def __init__(self, rate, clock=time.monotonic, sleep=time.sleep):
        self.interval = 1.0 / rate
        self.clock, self.sleep = clock, sleep
        self.lock = threading.Lock()
        self.next = None

    def wait(self):
        with self.lock:
            now = self.clock()
            start = now if self.next is None or self.next < now else self.next
            self.next = start + self.interval
        if start > now:
            self.sleep(start - now)


def tcp_connect(ip, port, timeout):
    """True if a TCP connection to IP:PORT is accepted."""
    family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((str(ip), port)) == 0


class Scanner:
    def __init__(self, perimeter, rate=100, timeout=1.0, threads=32, stop=None,
                 connect=tcp_connect):
        self.perimeter = perimeter
        self.limit = RateLimit(rate)
        self.timeout = timeout
        self.threads = threads
        self.stop = stop or threading.Event()
        self.connect = connect
        self.attempts = 0
        self.refused = 0
        self.lock = threading.Lock()

    def probe(self, ip, port):
        if not self.perimeter.contains(ip):
            with self.lock:
                self.refused += 1
            raise OutsidePerimeter(f"{ip} is outside every active authorized network")
        self.limit.wait()
        with self.lock:
            self.attempts += 1
        try:
            return self.connect(ip, port, self.timeout)
        except OSError as exc:
            log.debug("%s:%s: %s", ip, port, exc)
            return False

    def scan(self, network, ports):
        """[(ip, port)] open in NETWORK (an ip_network) among PORTS, in order.

        Stops at the first address outside the perimeter: the network was deactivated or
        removed during the scan.
        """
        found = []
        slots = threading.BoundedSemaphore(self.threads * 4)
        failure = []

        def task(ip, port):
            try:
                if not failure and not self.stop.is_set() and self.probe(ip, port):
                    with self.lock:
                        found.append((ip, port))
            except OutsidePerimeter as exc:
                failure.append(exc)
            finally:
                slots.release()

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            for ip in network.hosts():
                for port in ports:
                    if failure or self.stop.is_set():
                        break
                    self.perimeter.refresh(force=False)
                    slots.acquire()
                    pool.submit(task, ip, port)
                if failure or self.stop.is_set():
                    break
        if failure:
            raise failure[0]
        return sorted(found, key=lambda item: (item[0].version, item[0], item[1]))
