# aridi

Linux information gathering and infrastructure scanner

aridi profiles a Linux machine from the inside. A POSIX `sh` script collects raw data
from the machine, and a Python core turns it into a snapshot and a readable report:
hardware, distribution and kernel, installed packages, storage, dangerous permissions,
identity and banners, users and groups, services, network, firewall, time
synchronisation, processes, load, sessions, connections, the IP addresses and host names
mentioned in `/etc`, `/var/log` and the journal, and the neighbour table. It also builds
a **relation map**: for each IPv4 or IPv6 address, how it relates to the machine (DNS
server, login source, connected peer, firewall rule, named in a file…).

What it could not see is never left out: every area and every missing piece says why
(`denied`, `missing`, `na`, `timeout` or `error`).

**Who it is for:** system administrators, security teams and auditors who want a
readable, complete snapshot of a Linux machine.

## Project status

aridi was written in 2019 as a single Python program, and is being rewritten
([`docs/CAMBIO.md`](docs/CAMBIO.md), plan in [`TODO.md`](TODO.md)). The rewrite has
reached **feature parity with the 2019 program for local use**, and the 2019 code has
been removed (it stays in the git history).

What exists today:

- the **local mode**: collect on the machine, interpret anywhere;
- the **central component** (Django, SQLite, `docker compose`): it collects machines over
  SSH on demand or on a schedule, imports local collections, keeps the history of
  snapshots and what could not be seen, and searches the fleet. A web interface with two
  roles, administration and read-only.

What is planned and **does not exist yet**: change detection and alerts between
snapshots, and network discovery from the central component.

The measured, feature-by-feature status is in [`docs/MVP.md`](docs/MVP.md).

## Requirements

- **On the inspected machine:** Linux and a POSIX `sh` (dash, bash, busybox ash).
  Nothing else to install: no Python, no third-party packages. It uses the tools the
  distribution already ships when they are present (`ip`, `ss`, `lsblk`, `rpm`,
  `systemctl`…) and reads `/proc` and `/sys` otherwise. Root gives the full picture; as
  a regular user, what cannot be read is marked `denied`.
- **Where the bundle is interpreted:** Python 3.12 or later, standard library only. It
  can be the same machine or any other.

Tested on Debian 12 and 13, Ubuntu 24.04, Rocky 9, Fedora 44, Alpine 3.20, Arch,
openSUSE Leap 15.6, CentOS 7 and CentOS 6 (containers), plus Debian 12 (arm64 and amd64)
and Rocky 9 (arm64) VMs.

## Installation

```sh
git clone https://github.com/dpgon/aridi.git
cd aridi
```

Nothing else is needed. The collector is the single file `collector/aridi-collect.sh`;
copy it to the machine you want to inspect. The core runs from the repository with
`PYTHONPATH=src python3 -m aridi.cli …`, without installing anything.

Optionally, `pip install .` installs the `aridi` command. The core has no dependencies,
but **pip downloads `setuptools` from PyPI to build the package** (`[build-system]` in
`pyproject.toml`). If you want to avoid any third-party download, use the `PYTHONPATH`
form.

## Usage

Two steps:

```sh
# 1. On the machine to inspect (as root for the full picture)
sh aridi-collect.sh > host.aridi

# 2. Anywhere with Python 3.12, from the repository
export PYTHONPATH=src                # not needed after "pip install ."
python3 -m aridi.cli report host.aridi                # summary report
python3 -m aridi.cli report --detail host.aridi       # detailed report
python3 -m aridi.cli interpret host.aridi -o host.json   # snapshot as JSON
python3 -m aridi.cli validate host.aridi              # check the bundle format only
```

After `pip install .`, `aridi report host.aridi` is the same as
`python3 -m aridi.cli report host.aridi`.

The script can also be fed through a pipe, for example `ssh host sh -s <
aridi-collect.sh > host.aridi`. To collect many machines regularly, use the central
component (below).

## Central component

The central component runs in Docker: a web service (gunicorn) and a worker that runs the
collections over SSH, both from the image built by the `Dockerfile`, with SQLite in the
`aridi-data` volume. Third-party Python code comes only from
`requirements/central.txt`, installed with `--require-hashes`.

### Preparing a machine

On every machine to inventory, as root:

```sh
useradd -m -s /bin/sh aridi
install -d -o aridi -g aridi -m 0700 /home/aridi/.ssh
cat aridi.pub > /home/aridi/.ssh/authorized_keys   # the public key of the central
chown aridi:aridi /home/aridi/.ssh/authorized_keys && chmod 0600 /home/aridi/.ssh/authorized_keys

install -D -o root -g root -m 0755 aridi-collect.sh /usr/local/libexec/aridi-collect.sh
echo 'aridi ALL=(root) NOPASSWD: /usr/local/libexec/aridi-collect.sh ""' > /etc/sudoers.d/aridi
chmod 0440 /etc/sudoers.d/aridi && visudo -c
```

- **Why an installed script:** the sudo rule allows that one file, without arguments. Whoever
  gets aridi's key can run the collector, which only reads, and nothing else as root. A
  rule allowing `sh` would give root on the whole fleet.
- **Keep the path root-owned:** `/usr/local/libexec`, `/usr/local` and `/usr` must not be
  writable by other users, or the rule becomes full root.
- **Updating:** every collection compares the SHA-256 of the installed script with the
  central's copy; the machine page says when it is outdated. Install the new version
  with the same `install` command.
- **Without sudo:** set the machine's privilege to "the SSH user"; the central then sends
  the script through stdin and what needs root is reported as `denied`.
- **Host keys:** add the machine to the `known_hosts` file of the central
  (`ssh-keyscan` from a trusted network, then check the fingerprints). Checking is
  strict: an unknown or changed key fails the collection.

### Preparing the central

```sh
export ARIDI_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(50))')"
export ARIDI_ALLOWED_HOSTS=aridi.example.org
export ARIDI_CSRF_TRUSTED_ORIGINS=https://aridi.example.org
export ARIDI_KNOWN_HOSTS_FILE=/etc/aridi/known_hosts
export ARIDI_SSH_AUTH_SOCK=/run/aridi/ssh-agent.sock      # see below
docker compose up -d --build
docker compose exec web python -m aridi_central.manage createsuperuser
```

- **TLS is the proxy's job.** gunicorn listens on `127.0.0.1:8000` only. Put a reverse
  proxy with TLS in front of it that sets `X-Forwarded-Proto: https` (and removes it from
  client requests). Cookies are secure-only and HSTS is on by default
  (`ARIDI_HSTS_SECONDS`).
- **SSH credentials are never stored.** The worker uses an ssh-agent through the
  socket in `ARIDI_SSH_AUTH_SOCK`. **ssh-agent only answers clients with its own uid,
  and the containers run as uid 10001.** On Linux, run a dedicated agent as uid 10001
  (for example a system user `aridi` with that uid, `ssh-agent -a /run/aridi/ssh-agent.sock`,
  then `ssh-add` the key). Docker Desktop offers the host's agent at
  `/run/host-services/ssh-auth.sock`; whether it accepts uid 10001 has **not** been tested
  by the project, and it exposes every key of your own agent. The tests use a dedicated
  agent running as uid 10001 (`tests/central/compose.smoke.yaml`). An `ssh_config` can be
  added with `ARIDI_SSH_CONFIG_FILE`.
- **Users and roles:** create users with the superuser in
  `python -m aridi_central.manage shell` or `createsuperuser`, and put them in the
  `administration` or `read-only` group. Read-only users can see everything and change
  nothing.
- **Local collections** can be imported from the web (Import) or with
  `docker compose exec web python -m aridi_central.manage aridi_import FILE --machine NAME`.
- **Raw bundles** of the 10 most recent collections of each machine are kept compressed
  (`ARIDI_RAW_RETENTION`), so they can be interpreted again by a newer core.

### Backups

The database is a single SQLite file in the `aridi-data` volume. Copy it consistently,
while the services run, with SQLite's online backup:

```sh
docker compose exec web sqlite3 /data/aridi.db ".backup /data/backup.db"
docker compose cp web:/data/backup.db ./aridi-$(date +%F).db
docker compose exec web rm /data/backup.db
```

To restore, stop the services, replace `/data/aridi.db` with the copy **and delete the
`aridi.db-wal` and `aridi.db-shm` files of the old database**, then start them again:

```sh
docker compose stop
docker compose run --rm --no-deps -v "$PWD":/restore web sh -c \
  'cp /restore/aridi-DATE.db /data/aridi.db && rm -f /data/aridi.db-wal /data/aridi.db-shm'
docker compose up -d
```

The backup holds sensitive data about the whole fleet: store it like the database itself.

**Exit codes of `aridi`:** 0, everything was seen; 1, the snapshot has gaps (listed under
"What could not be seen"); 2, the bundle could not be read.

**What the script does not do:** it never writes to disk (everything goes to stdout), it
asks no questions, it changes nothing on the machine, and it does not scan the network.
It filters secrets at the source: password hashes are reduced to their algorithm, process
command lines are truncated and values that look like secrets are masked, and the IP
search sends file, line and address, never the text of the line. The details and the
known limits are in [`docs/FORMATO.md`](docs/FORMATO.md).

**The bundle and the report are sensitive:** they describe the machine in depth. Keep them
like any other security inventory. `aridi interpret -o` creates its file with mode 0600
and never overwrites an existing file.

## What changed from the 2019 program

The 2019 command line (`aridi.py -g -s -v -c -a --scan --graph -os -od -of -oi`) and its
report format are gone. In particular:

- the ARP sweep and the port scan from the machine are dropped: the collector is passive.
  Scanning is planned for the central component, limited to authorised networks;
- the `--graph` network graph is dropped; the snapshot carries the relations to draw it;
- host names found in files are listed, not resolved with DNS;
- reading the report needs Python 3.12 on some computer; the machine itself only needs
  `sh`.

The full list is in [`docs/CAMBIO.md`](docs/CAMBIO.md) (*Qué se pierde*), and the
feature-by-feature comparison with 2019, with the tests that prove it, is in
[`tests/parity.md`](tests/parity.md).

## Tests

All tests run in Docker; the host only needs a POSIX shell and Docker:

```sh
tests/run.sh all        # or: unit | collector | central | golden
```

- **`unit`:** the core tests in `python:3.12-slim`, against the sample corpus in
  `tests/corpus/` (10 distributions in three variants, plus three VMs) and the 2019
  comparison in `tests/parity/`.
- **`collector`:** the script in every corpus image, with every shell available, as root
  and as an unprivileged user: it must end with 0 and leave no trace on the machine.
- **`central`:** the central component in its test image: `check --deploy`, the Django
  tests, a real SSH collection from a disposable container, and a smoke test of
  `docker compose` (login, collection through ssh-agent, backup and restore).
- **`golden`:** regenerates the reference report of the unit tests (review the diff).

`tests/lima/central-acceptance.sh` runs the acceptance of the central component against a
disposable Lima VM (it needs Lima and Docker Desktop).

## Documentation

The project documentation lives in [`docs/`](docs/) and is written in **Spanish**:

| Document | Contents |
|---|---|
| [`docs/ESTUDIO.md`](docs/ESTUDIO.md) | Study of the 2019 code: what it did, how, and its known issues |
| [`docs/IDEA.md`](docs/IDEA.md) | Product idea: purpose, users, capabilities, principles, non-goals, glossary |
| [`docs/MVP.md`](docs/MVP.md) | What works today, measured feature by feature with the automated tests |
| [`docs/FUTURE.md`](docs/FUTURE.md) | Planned stages: central inventory, change alerts, scoped network discovery |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Architecture of the collector and the core, decision log, technical debt |
| [`docs/CAMBIO.md`](docs/CAMBIO.md) | The rewrite: what is kept, rewritten or dropped, target architecture, what is lost |
| [`docs/FORMATO.md`](docs/FORMATO.md) | Contract: raw bundle v1, snapshot v1, versioning policy, core CLI |

The work plan is [`TODO.md`](TODO.md), and the parity check against 2019 is
[`tests/parity.md`](tests/parity.md). Contributor and AI-agent working rules are in
[`CLAUDE.md`](CLAUDE.md). All of them are in Spanish.

## License

GPL v3. See [`LICENSE`](LICENSE).
