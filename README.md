# aridi

Linux information gathering and infrastructure scanner

aridi is a command-line tool that profiles a Linux machine from the inside. You run it
locally, as root, and it prints a text report covering the hardware, distribution,
kernel, installed packages, disks, users and groups, services, network configuration,
firewall rules, processes, open connections and login history. It also finds the IP
addresses and host names mentioned in `/etc` and `/var/log`, and builds an
**infrastructure map** that lists, for each IP, how it relates to the machine (DNS
server, login source, connected peer, firewall rule…). As an option, it can sweep the
local network with ARP and scan TCP ports.

It uses only the Python standard library, plus the tools that the distribution already
ships. The only exception is the optional network graph (`--graph`), which needs
`graphviz`.

**Who it is for:** system administrators, security teams and auditors who want a quick,
readable snapshot of a single Linux machine.

## Project status

> **Read this before using it.** aridi was written in March–April 2019 and was left as a
> *beta*. In October 2026 it was run unmodified in disposable containers (Debian 12,
> Ubuntu 24.04, Rocky 9, Fedora 44, Alpine 3.20, CentOS 7). It starts and finishes on
> Python 3.6 through 3.14, but on current systems **several sections disappear or report
> wrong data without any warning**. Some examples:
>
> - yescrypt password hashes are reported as "no password";
> - IPv6 listeners are invisible;
> - the disk section breaks with current `lsblk`;
> - all network information is lost when an interface is named like `eth0@if5`;
> - packages are missing on Fedora and Alpine.
>
> The measured, feature-by-feature status is in [`docs/MVP.md`](docs/MVP.md).

**A full rewrite is in progress.** The goals are:

- a dependency-free collector: a POSIX `sh` script plus a Python 3.12 interpreter;
- remote execution over SSH;
- a central inventory with history, change detection and alerts.

The decision and its trade-offs are in [`docs/CAMBIO.md`](docs/CAMBIO.md), and the work
plan is in [`TODO.md`](TODO.md). Until the rewrite reaches feature parity, the 2019
program described below lives, unmodified, in [`legacy/`](legacy/). Nothing from the
rewrite is usable yet.

## Requirements

- Linux.
- Python 3.6 or later. It was observed working on 3.6.8 to 3.14.8; no minimum version is
  declared. Python 3.12+ prints about 30 `SyntaxWarning` messages, which are harmless.
- Root privileges for the full report. It also runs as a regular user, with less
  information.
- Optional system tools, used when present: `lsusb`, `lsblk`, `findmnt`, `df`, `ip`,
  `iptables`, `systemctl` or `chkconfig`, `utmpdump`, `nslookup` or `dig`, and your
  package manager (`dpkg-query`, `apt`, `yum`, `zypper` or `pacman`). When a tool is
  missing, its section is skipped.
- Optional, only for `--graph`: `pip install graphviz` and the Graphviz `neato` binary.

## Installation

There is no package and nothing to build. Copy the repository to the machine; the 2019
program is in `legacy/`:

```sh
git clone https://github.com/dpgon/aridi.git
```

## Usage

Run it **from inside the `legacy/` directory**. `services.csv` is loaded from the current
directory; otherwise port names cannot be loaded and the scan is disabled. All output
files are also written to the current directory.

```sh
cd aridi/legacy
sudo python3 aridi.py                     # general information, summarized report
sudo python3 aridi.py -a -od report.txt   # everything, detailed report to a file
sudo python3 aridi.py -s -oi              # specific information, infrastructure map only
```

| Option | Meaning |
|---|---|
| `-g` | General information: hardware, OS, packages, disks, permission sweep (default) |
| `-s` | Specific information: identity, users, services, network, iptables (implies `-g`) |
| `-v` | Volatile information: processes, memory, CPU, disk load, sessions, connections |
| `-c` | Carving: IPs and host names in `/etc` and `/var/log` |
| `-a` | All of the above |
| `--scan` | ARP sweep of local subnets (root only) and TCP port scan of the IPs you choose |
| `--graph` | Draw the network graph (`network.dot`), requires `graphviz` |
| `-os` / `-od` / `-of` / `-oi` | Summarized (default) / detailed / full / infrastructure report |
| `-V LEVEL` | Log verbosity, from -1 to 3 (default 2) |
| `FILE` | Save the report to `FILE` instead of printing it |

**aridi is interactive.** It asks up to seven `(y/N)` questions while it runs, for
example before the filesystem permission sweep, the DNS lookups and the scan. Without a
terminal those sections are lost, and a non-root run aborts.

**Files it writes in the current directory:** `aridi.log`, `aridi.badfiles` (when the
permission sweep runs), `network.dot` (with `--graph`) and `FILE`. They are created with
fixed names and default permissions, and the report contains sensitive information. Do
not run it in a shared directory such as `/tmp`.

**About `--scan`:** the port scan can target any IP in the infrastructure map, including
third-party addresses found only in log files. Only scan networks you are authorized to
scan.

## Tests

All tests run in Docker; the host only needs a POSIX shell and Docker:

```sh
tests/run.sh all        # or: unit | collector | central | legacy
```

- **`unit`** runs the core unit tests in `python:3.12-slim`.
- **`legacy`** runs the 2019 program in disposable Debian 12 and CentOS 7 containers
  without network, and checks that its behaviour matches the recorded baseline in
  `tests/legacy/baseline/`.

The status of the 2019 program was measured by hand in the same way; see
[`docs/MVP.md`](docs/MVP.md#cómo-se-ha-medido).

## Documentation

The project documentation lives in [`docs/`](docs/) and is written in **Spanish**:

| Document | Contents |
|---|---|
| [`docs/ESTUDIO.md`](docs/ESTUDIO.md) | Code study: what the program does, how, its state and its known issues |
| [`docs/IDEA.md`](docs/IDEA.md) | Product idea: purpose, users, capabilities, principles, non-goals, glossary |
| [`docs/MVP.md`](docs/MVP.md) | What works today, measured feature by feature, and what is half-done or abandoned |
| [`docs/FUTURE.md`](docs/FUTURE.md) | Planned stages: reliable collector, central inventory, change alerts, scoped network discovery |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Current architecture, data model, interfaces, decision log, technical debt |
| [`docs/CAMBIO.md`](docs/CAMBIO.md) | The rewrite: what is kept, rewritten or dropped, target architecture, what is lost, alternatives, stages, risks |

The work plan of the rewrite is [`TODO.md`](TODO.md). Contributor and AI-agent working
rules are in [`CLAUDE.md`](CLAUDE.md). Both are in Spanish.

## License

GPL v3. See [`LICENSE`](LICENSE).
