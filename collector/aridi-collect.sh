#!/bin/sh
# aridi-collect.sh: raw collector of aridi.
#
# Runs on the inventoried machine (POSIX sh, no other requirement), reads what it can
# and writes a raw bundle to stdout. It never writes to disk and never sends secrets:
# sensitive data is filtered at the source. The bundle format is specified in
# docs/FORMATO.md.
#
# Usage: sh aridi-collect.sh > machine.aridi      or      ssh host sh -s < aridi-collect.sh
#
# The script may arrive through stdin ("sh -s"), so every command runs with </dev/null:
# a command that reads stdin would eat the rest of the script (bash reads it line by line).
#
# Copyright (C) 2019-2026 the aridi authors
# License: GNU General Public License v3.0 only (see LICENSE)

ARIDI_COLLECTOR_VERSION="2.0.0.dev0"
ARIDI_BUNDLE_FORMAT=1

# Limits per section. They can be lowered by the tests (tests/collector/).
ARIDI_SECTION_LIMIT=${ARIDI_SECTION_LIMIT:-4194304}
ARIDI_SECTION_TIMEOUT=${ARIDI_SECTION_TIMEOUT:-60}

# System directories first: a writable /usr/local must not shadow the base tools.
PATH=/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin
LC_ALL=C
export PATH LC_ALL
umask 077

# fd 3 is the bundle stream: section content is written there from inside the command
# substitutions that capture exit codes and stderr.
exec 3>&1

_count=0
_ok_rc=0

have() { command -v "$1" >/dev/null 2>&1; }

_line() { printf '%s\n' "--$_boundary $*"; }

_detect_timeout() {
    # Sets _timeout: "timeout" (coreutils), "watcher" (our own, see _watch) or empty.
    # The busybox timeout is not used: its watcher process inherits the output pipe and
    # checks only once per second, so every section would wait up to 1 s more.
    _timeout=""
    _timeout_kind=none
    if timeout --version </dev/null >/dev/null 2>&1 &&
        timeout 5 true </dev/null >/dev/null 2>&1; then
        _timeout=timeout
        _timeout_kind=coreutils
    elif sleep 0 </dev/null >/dev/null 2>&1 && kill -0 $$ 2>/dev/null; then
        _timeout=watcher
        _timeout_kind=watcher
    fi
}

_watch() {
    # Runs "$@" and kills it with TERM after ARIDI_SECTION_TIMEOUT seconds. The watcher
    # holds none of the section's descriptors, and its sleep is killed with it.
    "$@" &
    _cmd_pid=$!
    (
        sleep "$ARIDI_SECTION_TIMEOUT" &
        _sleep_pid=$!
        trap 'kill "$_sleep_pid" 2>/dev/null; exit 0' TERM
        wait "$_sleep_pid" && kill -TERM "$_cmd_pid" 2>/dev/null
    ) </dev/null >/dev/null 2>&1 3>&- 4>&- 5>&- &
    _watcher_pid=$!
    wait "$_cmd_pid"
    _watch_rc=$?
    kill -TERM "$_watcher_pid" 2>/dev/null
    wait "$_watcher_pid" 2>/dev/null
    return $_watch_rc
}

_new_boundary() {
    _boundary=$(od -An -N16 -tx1 /dev/urandom 2>/dev/null </dev/null | tr -d ' \n')
    _boundary_source=urandom
    case $_boundary in
        ????????????????????????????????) ;;
        *)
            # Weak fallback, declared in meta.env: time and pid only.
            _boundary="weak$(date +%s 2>/dev/null </dev/null)x$$"
            _boundary_source=weak
            ;;
    esac
}

_limited() {
    # Runs "$@" with the section time limit.
    case $_timeout in
        timeout) timeout "$ARIDI_SECTION_TIMEOUT" "$@" ;;
        watcher) _watch "$@" ;;
        *) "$@" ;;
    esac
}

_stderr_line() {
    # One printable line of at most 400 bytes from stdin, prefixed with "err ". It reads
    # all its input: closing the pipe early would kill the command with SIGPIPE.
    # Control and non-ASCII bytes become "?" (busybox tr has no character classes).
    _e=$(awk 'length(s) < 400 { s = s " " $0 } END { s = substr(s, 2, 400)
        gsub(/[^ -~]/, "?", s); print s }')
    [ -n "$_e" ] && printf 'err %s\n' "$_e"
    return 0
}

_run() {
    # _run NAME FIELDS COMMAND...: one section with the output of COMMAND.
    _name=$1
    _fields=$2
    shift 2
    _count=$((_count + 1))
    _line "begin $_name $_fields limit=$ARIDI_SECTION_LIMIT"
    # Content goes to fd 3 (limit + 1 bytes, so the reader can tell it was cut); the exit
    # code and the first stderr bytes are captured.
    _res=$( { { { _limited "$@" </dev/null 2>&5; echo "rc $?" >&4; } |
        head -c "$((ARIDI_SECTION_LIMIT + 1))" >&3; } 5>&1 | _stderr_line; } 4>&1 )
    printf '\n'
    _rc=$(printf '%s\n' "$_res" | sed -n 's/^rc //p')
    _err=$(printf '%s\n' "$_res" | sed -n 's/^err //p')
    # _ok_rc: exit codes that are a normal result for this section (section_rc).
    case " $_ok_rc " in
        *" $_rc "*) _status=ok ;;
        *) _status=$(_status_of "$_rc" "$_err") ;;
    esac
    _ok_rc=0
    _line "end $_name status=$_status rc=${_rc:--}"
    [ -n "$_err" ] && _line "note $_name $_err"
    return 0
}

_status_of() {
    # _status_of RC STDERR: status of a section from its exit code and stderr.
    case $1 in
        0) echo ok ;;
        124|137|143) if [ -n "$_timeout" ]; then echo timeout; else echo error; fi ;;
        141) echo ok ;;  # SIGPIPE: the output exceeded the limit (marked by the reader)
        127) echo missing ;;
        *)
            case $2 in
                *"ermission denied"*|*"peration not permitted"*) echo denied ;;
                *) echo error ;;
            esac
            ;;
    esac
}

_empty() {
    # _empty NAME FIELDS STATUS NOTE: a section that was not run.
    _count=$((_count + 1))
    _line "begin $1 $2 limit=$ARIDI_SECTION_LIMIT"
    printf '\n'
    _line "end $1 status=$3 rc=-"
    _line "note $1 $4"
}

section() {
    # section NAME TOOL [ARGS...]: output of a command; "missing" if TOOL does not exist.
    _sname=$1
    shift
    if have "$1"; then
        _run "$_sname" "kind=cmd tool=${1##*/}" "$@"
    else
        _empty "$_sname" "kind=cmd tool=${1##*/}" missing "tool not found: $1"
    fi
}

section_rc() {
    # section_rc NAME CODES TOOL [ARGS...]: like section, but the exit codes in CODES
    # (space separated) are a normal result, e.g. "ldd --version" exits 1 on musl.
    _ok_rc="0 $2"
    _rname=$1
    shift 2
    section "$_rname" "$@"
    _ok_rc=0
}

section_file() {
    # section_file NAME PATH: content of a file; "na" if it does not exist, "denied" if
    # it cannot be read.
    if [ ! -e "$2" ]; then
        _empty "$1" "kind=file path=$2" na "not found: $2"
    elif [ ! -r "$2" ]; then
        _empty "$1" "kind=file path=$2" denied "not readable: $2"
    else
        _run "$1" "kind=file path=$2" cat "$2"
    fi
}

section_text() {
    # section_text NAME TEXT: a value computed by the script itself.
    _count=$((_count + 1))
    _line "begin $1 kind=text limit=$ARIDI_SECTION_LIMIT"
    printf '%s\n\n' "$2"
    _line "end $1 status=ok rc=0"
}

bundle_begin() {
    _new_boundary
    _detect_timeout
    printf 'ARIDI-BUNDLE %s %s\n' "$ARIDI_BUNDLE_FORMAT" "$ARIDI_COLLECTOR_VERSION"
    printf 'boundary %s\n' "$_boundary"
}

bundle_end() {
    _line "close sections=$_count"
}

collect_meta() {
    # Identity of the machine and of this run (snapshot header, docs/FORMATO.md).
    _shell=$(readlink "/proc/$$/exe" 2>/dev/null </dev/null)
    section_text meta.env "shell=${_shell:-unknown}
timeout=$_timeout_kind
section_timeout=$ARIDI_SECTION_TIMEOUT
section_limit=$ARIDI_SECTION_LIMIT
boundary_source=$_boundary_source
path=$PATH"
    section meta.date_utc date -u +%Y-%m-%dT%H:%M:%SZ
    section meta.uid id -u
    section_file meta.machine_id /etc/machine-id
    section_file meta.dbus_machine_id /var/lib/dbus/machine-id
    section_file meta.hostname /proc/sys/kernel/hostname
    section meta.uname uname -a
}

collect_system() {
    # 3.1 System: distribution, kernel and libc.
    section_file system.os_release /etc/os-release
    section_file system.os_release_usr /usr/lib/os-release
    section_file system.centos_release /etc/centos-release
    section_file system.redhat_release /etc/redhat-release
    section_file system.fedora_release /etc/fedora-release
    section_file system.suse_release /etc/SuSE-release
    section_file system.debian_version /etc/debian_version
    section_file system.slackware_version /etc/slackware-version
    section_file system.alpine_release /etc/alpine-release
    section_file system.lsb_release /etc/lsb-release
    section_file system.kernel_ostype /proc/sys/kernel/ostype
    section_file system.kernel_osrelease /proc/sys/kernel/osrelease
    section_file system.kernel_version /proc/sys/kernel/version
    section_file system.proc_version /proc/version
    section system.machine uname -m
    # glibc prints its version on stdout and exits 0; musl prints it on stderr and exits 1.
    if have ldd; then
        section_rc system.ldd_version 1 sh -c 'ldd --version 2>&1'
    else
        _empty system.ldd_version "kind=cmd tool=ldd" missing "tool not found: ldd"
    fi
    section system.getconf_libc getconf GNU_LIBC_VERSION
    section system.musl_loader sh -c 'ls -1 /lib/ld-musl-* 2>/dev/null; exit 0'
}

collect_hardware() {
    # 3.2 Hardware: CPU, memory and USB (from /proc and /sys, without lsusb).
    section_file hardware.cpuinfo /proc/cpuinfo
    section_file hardware.cpu_online /sys/devices/system/cpu/online
    section_file hardware.cpu_present /sys/devices/system/cpu/present
    if [ -d /sys/devices/system/cpu ]; then
        # One line per CPU: name, package, core and thread siblings.
        section hardware.cpu_topology sh -c '
            for d in /sys/devices/system/cpu/cpu[0-9]*; do
                [ -d "$d/topology" ] || continue
                t=$d/topology
                echo "${d##*/} package=$(cat $t/physical_package_id 2>/dev/null)" \
                    "core=$(cat $t/core_id 2>/dev/null)" \
                    "die=$(cat $t/die_id 2>/dev/null)" \
                    "cluster=$(cat $t/cluster_id 2>/dev/null)" \
                    "threads=$(cat $t/thread_siblings_list 2>/dev/null)" \
                    "online=$(cat $d/online 2>/dev/null)"
            done'
    else
        _empty hardware.cpu_topology "kind=cmd tool=sh" na "no /sys/devices/system/cpu"
    fi
    section hardware.machine uname -m
    section hardware.lscpu lscpu
    section_file hardware.meminfo /proc/meminfo
    if [ -d /sys/bus/usb/devices ]; then
        # One block per device: "device NAME" and then attribute=value lines.
        section hardware.usb sh -c '
            for d in /sys/bus/usb/devices/*; do
                [ -f "$d/idVendor" ] || continue
                echo "device ${d##*/}"
                for a in idVendor idProduct bDeviceClass busnum devnum speed \
                    manufacturer product; do
                    [ -r "$d/$a" ] && echo "$a=$(head -c 200 "$d/$a" | tr -d "\n")"
                done
                echo
            done'
    else
        _empty hardware.usb "kind=cmd tool=sh" na "no /sys/bus/usb/devices"
    fi
}

collect_packages() {
    # 3.3 Installed packages: package databases read directly, only the needed fields.
    if [ -f /var/lib/dpkg/status ]; then
        section packages.dpkg awk '/^(Package|Status|Version|Architecture):/ || /^$/' \
            /var/lib/dpkg/status
    else
        _empty packages.dpkg "kind=cmd tool=awk" na "no /var/lib/dpkg/status"
    fi
    if [ -f /lib/apk/db/installed ]; then
        section packages.apk awk '/^[PVA]:/ || /^$/' /lib/apk/db/installed
    else
        _empty packages.apk "kind=cmd tool=awk" na "no /lib/apk/db/installed"
    fi
    if [ -d /var/lib/pacman/local ]; then
        section packages.pacman sh -c '
            for f in /var/lib/pacman/local/*/desc; do
                [ -f "$f" ] || continue
                awk "/^%(NAME|VERSION|ARCH)%\$/ { key = \$0; getline; print key, \$0 }
                     END { print \"\" }" "$f"
            done'
    else
        _empty packages.pacman "kind=cmd tool=awk" na "no /var/lib/pacman/local"
    fi
    if [ -d /var/lib/rpm ] || [ -d /usr/lib/sysimage/rpm ]; then
        # As root, rpm writes to its database directory just by reading it (Berkeley DB
        # environment files __db.*, SQLite -shm). It runs as uid 65534 instead, through
        # "chroot --userspec" (coreutils, present where setpriv is not), so it cannot.
        _rpm_qf='%{NAME}\t%{EPOCH}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n'
        if [ "$(id -u)" = 0 ] &&
            chroot --userspec=65534:65534 / true </dev/null >/dev/null 2>&1; then
            section packages.rpm chroot --userspec=65534:65534 / rpm -qa --qf "$_rpm_qf"
        else
            section packages.rpm rpm -qa --qf "$_rpm_qf"
        fi
    else
        _empty packages.rpm "kind=cmd tool=rpm" na "no rpm database"
    fi
}

collect_storage() {
    # 3.4 Storage: block devices, mounts (all of them, bind and subvolumes) and usage.
    section_file storage.partitions /proc/partitions
    section_file storage.mountinfo /proc/self/mountinfo
    section_file storage.swaps /proc/swaps
    if [ -d /sys/class/block ]; then
        # One line per block device; sizes in 512-byte sectors, as the kernel gives them.
        section storage.block sh -c '
            for d in /sys/class/block/*; do
                [ -f "$d/size" ] || continue
                kind=disk
                [ -f "$d/partition" ] && kind=part
                echo "${d##*/} kind=$kind size=$(cat $d/size)" \
                    "removable=$(cat $d/removable 2>/dev/null)" \
                    "ro=$(cat $d/ro 2>/dev/null)" \
                    "dev=$(cat $d/dev 2>/dev/null)" \
                    "dm=$(cat $d/dm/name 2>/dev/null)" \
                    "holders=$(ls $d/holders 2>/dev/null | tr "\n" ",")" \
                    "slaves=$(ls $d/slaves 2>/dev/null | tr "\n" ",")"
            done'
    else
        _empty storage.block "kind=cmd tool=sh" na "no /sys/class/block"
    fi
    section storage.df df -P -k
    if have lsblk; then
        # Key="value" pairs (-P); PKNAME is missing in old util-linux.
        section storage.lsblk sh -c '
            lsblk -P -b -o NAME,KNAME,PKNAME,TYPE,SIZE,RM,RO,FSTYPE,MOUNTPOINT 2>/dev/null ||
                lsblk -P -b -o NAME,KNAME,TYPE,SIZE,RM,RO,FSTYPE,MOUNTPOINT'
    else
        _empty storage.lsblk "kind=cmd tool=lsblk" missing "tool not found: lsblk"
    fi
}

collect_permissions() {
    # 3.5 Dangerous permissions on the local root filesystem (-xdev). One line per entry:
    # raw mode in hex (type and permission bits), uid, gid and path. "stat -c" works the
    # same in GNU and busybox, unlike "find -printf". Symbolic links are skipped: their
    # own mode is always 777.
    section permissions.find sh -c '
        find / -xdev ! -type l \( -perm -4000 -o -perm -2000 -o -perm -0002 \) \
            -exec stat -c "%f %u %g %n" {} +'
    # The account files, recovered from dangerousperm() of 2019.
    section permissions.account_files sh -c '
        for f in /etc/passwd /etc/group /etc/shadow /etc/gshadow; do
            [ -e "$f" ] || continue
            stat -c "%f %u %g %n" "$f" || echo "error $f"
        done'
}

collect_identity() {
    # 3.6 Identity and banners. Banners are untrusted text: sent as is, never interpreted.
    section identity.hostname hostname
    section_file identity.kernel_hostname /proc/sys/kernel/hostname
    section_file identity.etc_hostname /etc/hostname
    section_file identity.nis_domainname /proc/sys/kernel/domainname
    # dnsdomainname exits 1 when the host has no DNS domain.
    section_rc identity.dnsdomainname 1 dnsdomainname
    section identity.hostid hostid
    section_file identity.issue /etc/issue
    section_file identity.issue_net /etc/issue.net
    section_file identity.motd /etc/motd
    if [ -d /etc/motd.d ]; then
        # "==> FILE <==" before each file, like head; 64 KiB per file at most.
        section identity.motd_d sh -c '
            for f in /etc/motd.d/*; do
                [ -f "$f" ] || continue
                echo "==> $f <=="
                head -c 65536 "$f"
                echo
            done'
    else
        _empty identity.motd_d "kind=cmd tool=sh" na "no /etc/motd.d"
    fi
}

# awk program that replaces the password field ($2) with its prefix: "$id$" of the hash
# algorithm (up to the second "$"), preceded by the "!" lock marks, or "", "*", "x", "des"
# (13 characters of the crypt alphabet), "bsdi" (20 starting with "_") or "other" (any
# other text, which no password can match). Only the shape is looked at.
# THE HASH NEVER LEAVES THE MACHINE: this is the only way password fields are read.
_PASSWORD_PREFIX_AWK='
BEGIN { FS = ":"; OFS = ":" }
{
    p = $2; lock = ""
    while (substr(p, 1, 1) == "!") { lock = lock "!"; p = substr(p, 2) }
    if (p == "" || p == "x") q = p
    else if (substr(p, 1, 1) == "*") q = "*"
    else if (substr(p, 1, 1) == "$") {
        n = index(substr(p, 2), "$")
        q = (n > 0 && n <= 8) ? substr(p, 1, n + 1) : "other"
    }
    else if (length(p) == 13 && p ~ /^[.\/0-9A-Za-z]+$/) q = "des"
    else if (length(p) == 20 && substr(p, 1, 1) == "_") q = "bsdi"
    else q = "other"
    $2 = lock q
    print
}'

_password_file() {
    # _password_file NAME PATH: PATH with its password field reduced to the prefix.
    if [ ! -e "$2" ]; then
        _empty "$1" "kind=file path=$2 filter=prefix" na "not found: $2"
    elif [ ! -r "$2" ]; then
        _empty "$1" "kind=file path=$2 filter=prefix" denied "not readable: $2"
    else
        _run "$1" "kind=file path=$2 filter=prefix" awk "$_PASSWORD_PREFIX_AWK" "$2"
    fi
}

collect_users() {
    # 3.7 Users and groups. Password fields are filtered at the source (see above).
    _password_file users.passwd /etc/passwd
    _password_file users.group /etc/group
    _password_file users.shadow /etc/shadow
    _password_file users.gshadow /etc/gshadow
}

collect_services() {
    # 3.8 Services: systemd only when it is running (a systemctl binary without systemd,
    # as in containers, is "na", not an error), SysV, OpenRC and runit.
    section_file services.init_comm /proc/1/comm
    if [ -d /run/systemd/system ]; then
        section services.systemd_units systemctl list-units --all --plain --no-legend \
            --no-pager --full
        section services.systemd_unit_files systemctl list-unit-files --no-legend --no-pager
    else
        _empty services.systemd_units "kind=cmd tool=systemctl" na "systemd is not running"
        _empty services.systemd_unit_files "kind=cmd tool=systemctl" na \
            "systemd is not running"
    fi
    # runlevel exits 1 ("unknown") when there is no utmp record.
    section_rc services.runlevel 1 runlevel
    section services.chkconfig chkconfig --list
    if [ -d /etc/rc.d ] || [ -d /etc/rc0.d ] || [ -d /etc/rc3.d ]; then
        # "DIR:" before the S/K links of each runlevel directory.
        section services.rc_d sh -c '
            for d in /etc/rc.d/rc[0-6S].d /etc/rc[0-6S].d; do
                [ -d "$d" ] || continue
                echo "$d:"
                ls -1 "$d"
            done'
    else
        _empty services.rc_d "kind=cmd tool=sh" na "no /etc/rc.d nor /etc/rcN.d"
    fi
    if [ -d /etc/runlevels ]; then
        section services.openrc_runlevels sh -c '
            for d in /etc/runlevels/*; do
                [ -d "$d" ] || continue
                echo "${d##*/}:"
                ls -1 "$d"
            done'
        section services.openrc_status rc-status -a
    else
        _empty services.openrc_runlevels "kind=cmd tool=sh" na "no /etc/runlevels"
        _empty services.openrc_status "kind=cmd tool=rc-status" na "no /etc/runlevels"
    fi
    if have sv && { [ -d /var/service ] || [ -d /etc/service ]; }; then
        section services.runit sh -c 'for s in /var/service/* /etc/service/*; do
            [ -e "$s" ] && sv status "$s"; done; exit 0'
    else
        _empty services.runit "kind=cmd tool=sv" na "no runit services"
    fi
}

collect_network() {
    # 3.9 Network: interfaces, addresses, routes, name resolution and sockets. /sys and
    # /proc are always read; "ip" only adds detail where it exists.
    section network.ip_link ip -o link
    section network.ip_addr ip -o addr
    section network.ip_route ip -o route show table main
    section network.ip_route6 ip -o -6 route show table main
    if [ -d /sys/class/net ]; then
        section network.sys_class_net sh -c '
            for d in /sys/class/net/*; do
                [ -d "$d" ] || continue
                echo "${d##*/} address=$(cat $d/address 2>/dev/null)" \
                    "operstate=$(cat $d/operstate 2>/dev/null) mtu=$(cat $d/mtu 2>/dev/null)" \
                    "type=$(cat $d/type 2>/dev/null) ifindex=$(cat $d/ifindex 2>/dev/null)" \
                    "iflink=$(cat $d/iflink 2>/dev/null)"
            done'
    else
        _empty network.sys_class_net "kind=cmd tool=sh" na "no /sys/class/net"
    fi
    section_file network.if_inet6 /proc/net/if_inet6
    section_file network.fib_trie /proc/net/fib_trie
    section_file network.proc_route /proc/net/route
    section_file network.proc_ipv6_route /proc/net/ipv6_route
    section_file network.hosts /etc/hosts
    section_file network.resolv_conf /etc/resolv.conf
    section_file network.resolved_resolv_conf /run/systemd/resolve/resolv.conf
    section_file network.proc_tcp /proc/net/tcp
    section_file network.proc_tcp6 /proc/net/tcp6
    section_file network.proc_udp /proc/net/udp
    section_file network.proc_udp6 /proc/net/udp6
    section_file network.proc_raw /proc/net/raw
    section_file network.proc_raw6 /proc/net/raw6
    # Socket inode -> PID: "PID INODE" for every socket descriptor, one ls for all.
    section network.socket_pids sh -c '
        ls -l /proc/[0-9]*/fd/ 2>/dev/null | awk "
            /^\/proc\/[0-9]+\/fd\/?:\$/ { split(\$0, p, \"/\"); pid = p[3]; next }
            /socket:\[/ { s = \$NF; gsub(/[^0-9]/, \"\", s); print pid, s }"'
    # PID -> uid and command name, one awk for all processes.
    section network.process_names sh -c '
        awk "FNR == 1 { split(FILENAME, p, \"/\"); pid = p[3] }
             /^Name:/ { name = \$2 }
             /^Uid:/ { print pid, \$2, name }" /proc/[0-9]*/status 2>/dev/null; exit 0'
}

collect_firewall() {
    # 3.10 Firewall. Each engine is queried only if it is already active in the kernel:
    # asking nft or iptables can make the kernel load modules, which would change the
    # system. All of them need root; without it they are "denied".
    # nf_tables is present as a module (/sys/module) or built into the kernel (kallsyms).
    if [ -d /sys/module/nf_tables ] ||
        grep -q -w nft_do_chain /proc/kallsyms </dev/null 2>/dev/null; then
        # JSON output exists since nft 0.9 (CentOS 7 has 0.8).
        if have nft && ! nft --help </dev/null 2>&1 | grep -q -- --json; then
            _empty firewall.nft_json "kind=cmd tool=nft" missing "nft has no JSON output"
        else
            section firewall.nft_json nft -j list ruleset
        fi
        section firewall.nft nft list ruleset
    else
        _empty firewall.nft_json "kind=cmd tool=nft" na "nf_tables is not in the kernel"
        _empty firewall.nft "kind=cmd tool=nft" na "nf_tables is not in the kernel"
    fi
    if [ -e /proc/net/ip_tables_names ]; then
        section firewall.iptables_legacy sh -c '
            if command -v iptables-legacy-save >/dev/null 2>&1; then iptables-legacy-save
            else iptables-save; fi'
    else
        _empty firewall.iptables_legacy "kind=cmd tool=iptables-save" na \
            "ip_tables is not loaded"
    fi
    if [ -e /proc/net/ip6_tables_names ]; then
        section firewall.ip6tables_legacy sh -c '
            if command -v ip6tables-legacy-save >/dev/null 2>&1; then ip6tables-legacy-save
            else ip6tables-save; fi'
    else
        _empty firewall.ip6tables_legacy "kind=cmd tool=ip6tables-save" na \
            "ip6_tables is not loaded"
    fi
    if have firewall-cmd && firewall-cmd --state </dev/null >/dev/null 2>&1; then
        section firewall.firewalld firewall-cmd --list-all-zones
    else
        _empty firewall.firewalld "kind=cmd tool=firewall-cmd" na "firewalld is not running"
    fi
    section firewall.ufw ufw status verbose
}

collect_timesync() {
    # 3.11 Time synchronization: configuration and, where the daemon runs, its sources.
    section_file timesync.chrony_conf /etc/chrony.conf
    section_file timesync.chrony_conf_debian /etc/chrony/chrony.conf
    section timesync.chronyc chronyc -n sources
    section_file timesync.ntp_conf /etc/ntp.conf
    section timesync.ntpq ntpq -pn
    if [ -f /etc/systemd/timesyncd.conf ] || [ -d /etc/systemd/timesyncd.conf.d ]; then
        # The main file and its drop-ins, in the order systemd reads them.
        section timesync.timesyncd_conf sh -c '
            for f in /etc/systemd/timesyncd.conf /etc/systemd/timesyncd.conf.d/*.conf; do
                [ -f "$f" ] || continue
                echo "==> $f <=="
                cat "$f"
            done'
    else
        _empty timesync.timesyncd_conf "kind=cmd tool=sh" na "no timesyncd configuration"
    fi
    if [ -d /run/systemd/system ]; then
        section timesync.timedatectl timedatectl show-timesync --all
    else
        _empty timesync.timedatectl "kind=cmd tool=timedatectl" na "systemd is not running"
    fi
}

# awk program that hides the values of password-like options in command lines:
# "--password=x", "--token x", "secret=x"... become "--password=***". It cannot catch
# every form (e.g. "mysql -pSECRET"): see docs/FORMATO.md. awk, not sed: busybox sed has
# no alternation in its regular expressions.
_SECRET_AWK='
{
    for (i = 2; i <= NF; i++) {
        low = tolower($i)
        if (low ~ /^-*[a-z_-]*(pass(wo?rd)?|pwd|token|secret|api[-_]?key)=/)
            $i = substr($i, 1, index($i, "=")) "***"
        else if (low ~ /^-*[a-z_-]*(pass(wo?rd)?|pwd|token|secret|api[-_]?key)$/ && i < NF)
            $(++i) = "***"
    }
    print
}'

collect_processes() {
    # 3.12 Processes: stat and status of every process, and its command line with "\0"
    # turned into spaces, cut at 512 bytes and with password-like values hidden.
    section processes.stat sh -c 'cat /proc/[0-9]*/stat 2>/dev/null; exit 0'
    section processes.status sh -c '
        awk "FNR == 1 { split(FILENAME, p, \"/\"); pid = p[3]; uid = \"\"; rss = \"\" }
             /^Uid:/ { uid = \$2 }
             /^VmRSS:/ { rss = \$2 }
             /^Threads:/ { print pid, uid, rss, \$2 }" /proc/[0-9]*/status 2>/dev/null
        exit 0'
    section processes.cmdline sh -c '
        for p in /proc/[0-9]*; do
            [ -r "$p/cmdline" ] || continue
            printf "%s " "${p#/proc/}"
            head -c 512 "$p/cmdline" 2>/dev/null | tr "\000\n" "  "
            echo
        done | awk "$1"' sh "$_SECRET_AWK"
    section_file processes.uptime /proc/uptime
    section processes.clk_tck getconf CLK_TCK
}

collect_load() {
    # 3.13 CPU, memory and disk usage: two samples of /proc/stat and /proc/diskstats one
    # second apart, each with its /proc/uptime for the exact interval.
    section_file load.uptime_1 /proc/uptime
    section_file load.stat_1 /proc/stat
    section_file load.diskstats_1 /proc/diskstats
    sleep 1
    section_file load.uptime_2 /proc/uptime
    section_file load.stat_2 /proc/stat
    section_file load.diskstats_2 /proc/diskstats
    section_file load.meminfo /proc/meminfo
    section_file load.loadavg /proc/loadavg
    section_file load.file_nr /proc/sys/fs/file-nr
    section_file load.inode_nr /proc/sys/fs/inode-nr
}

collect_sessions() {
    # 3.14 Sessions and logins: utmp/wtmp/btmp, wtmpdb/lastlog2 where wtmp is gone, and
    # the sshd messages of the journal or of the auth logs (last lines only).
    section sessions.who who
    for f in /run/utmp /var/log/wtmp /var/log/btmp; do
        n=${f##*/}
        if [ ! -e "$f" ]; then
            _empty "sessions.utmpdump_$n" "kind=cmd tool=utmpdump path=$f" na "not found: $f"
        elif [ ! -r "$f" ]; then
            _empty "sessions.utmpdump_$n" "kind=cmd tool=utmpdump path=$f" denied "not readable: $f"
        else
            section "sessions.utmpdump_$n" utmpdump "$f"
        fi
    done
    section sessions.wtmpdb wtmpdb last -F
    section sessions.lastlog2 lastlog2
    section sessions.last last -F -w
    section sessions.lastb lastb -F -w
    if [ -d /run/systemd/system ] && have journalctl; then
        section sessions.journal_sshd journalctl _COMM=sshd _COMM=sshd-session -o short-iso \
            --since -30d --no-pager -q -n 5000
    else
        _empty sessions.journal_sshd "kind=cmd tool=journalctl" na "systemd is not running"
    fi
    for f in /var/log/auth.log /var/log/secure /var/log/messages; do
        n=$(echo "${f##*/}" | tr . _)
        if [ -f "$f" ] && [ -r "$f" ]; then
            section "sessions.log_$n" sh -c 'tail -n 20000 "$1" | grep -E "sshd(-session)?\[" |
                tail -n 5000; exit 0' sh "$f"
        elif [ -f "$f" ]; then
            _empty "sessions.log_$n" "kind=cmd tool=tail path=$f" denied "not readable: $f"
        else
            _empty "sessions.log_$n" "kind=cmd tool=tail path=$f" na "not found: $f"
        fi
    done
}

# awk program that extracts IP addresses from "PATH:LINE:TEXT" lines (grep -Hn). It prints
# "PATH|LINE|IP|PREFIX|BEFORE|AFTER|FLAGS" per address and never the text of the line,
# which may hold secrets. BEFORE and AFTER classify the neighbour characters (d digit,
# l letter, p dot, s slash, k colon, h hyphen, w blank, x other, empty at the line edge);
# FLAGS has "c" for a commented line and "v" when "version" precedes the address. IPv6 candidates must look like an address:
# "::" or 7 colons, groups of at most 4 hex digits, at least one digit, and no single ":"
# at either end. That leaves out times, MAC addresses and "uid:gid::" of /etc/passwd.
_IP_AWK='
function cls(c) {
    if (c == "") return ""
    if (c ~ /[0-9]/) return "d"
    if (c ~ /[A-Za-z]/) return "l"
    if (c == ".") return "p"
    if (c == "/") return "s"
    if (c == ":") return "k"
    if (c == "-") return "h"
    if (c ~ /[ \t]/) return "w"
    return "x"
}
function ipv6_like(c,    n, parts, i) {
    if (c !~ /[0-9A-Fa-f]/) return 0
    if (c ~ /^:[^:]/ || c ~ /[^:]:$/) return 0
    n = split(c, parts, ":")
    if (n > 9) return 0
    for (i = 1; i <= n; i++) if (length(parts[i]) > 4) return 0
    return index(c, "::") || n == 8
}
function emit(addr, start, len,    pre, post, prefix, rest, flags) {
    pre = (start > 1) ? substr(line, start - 1, 1) : ""
    post = substr(line, start + len, 1)
    prefix = ""
    if (post == "/") {
        rest = substr(line, start + len + 1)
        if (match(rest, /^[0-9]+/)) prefix = substr(rest, 1, RLENGTH)
    }
    flags = comment
    if (index(tolower(substr(line, 1, start - 1)), "version")) flags = flags "v"
    print path "|" lineno "|" addr "|" prefix "|" cls(pre) "|" cls(post) "|" flags
}
{
    path = $0; sub(/:.*/, "", path)
    rest = substr($0, length(path) + 2)
    lineno = rest; sub(/:.*/, "", lineno)
    line = substr(rest, length(lineno) + 2)
    comment = (line ~ /^[ \t]*[#;]/) ? "c" : ""
    base = 0; s = line
    # emit() calls match() too: RSTART and RLENGTH are saved first.
    while (match(s, /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/)) {
        rs = RSTART; rl = RLENGTH
        emit(substr(s, rs, rl), base + rs, rl)
        base += rs + rl - 1; s = substr(s, rs + rl)
    }
    base = 0; s = line
    while (match(s, /[0-9A-Fa-f]*:[0-9A-Fa-f:]*:[0-9A-Fa-f]*/)) {
        rs = RSTART; rl = RLENGTH
        cand = substr(s, rs, rl)
        if (ipv6_like(cand)) emit(cand, base + rs, rl)
        base += rs + rl - 1; s = substr(s, rs + rl)
    }
}'

# awk program that lists possible host names (at least two dots, last label alphabetic) in
# "PATH:LINE:TEXT" lines of /etc, once per file: "PATH|NAME". Commented lines are skipped.
_FQDN_AWK='
{
    path = $0; sub(/:.*/, "", path)
    rest = substr($0, length(path) + 2)
    lineno = rest; sub(/:.*/, "", lineno)
    line = tolower(substr(rest, length(lineno) + 2))
    if (line ~ /^[ \t]*[#;<]/) next
    n = split(line, tokens, /[^a-z0-9.-]+/)
    for (i = 1; i <= n; i++) {
        t = tokens[i]
        sub(/^[.-]+/, "", t); sub(/[.-]+$/, "", t)
        if (t !~ /^[a-z0-9-]+\.[a-z0-9.-]+\.[a-z]+$/ || index(t, "..")) continue
        if (!seen[path SUBSEP t]++) print path "|" t
    }
}'

collect_carving() {
    # 3.16 IP addresses and names in /etc, /var/log and the journal: text files of less
    # than 1 MiB, only the addresses (see _IP_AWK), at most 20000 lines per section. In
    # /etc only files any user can read (-perm -0004): shadow, gshadow, private keys and
    # anything else protected are never opened.
    section carving.etc_ips sh -c '
        find /etc -xdev -type f -perm -0004 -size -1024k -exec grep -IEHn \
            -e "[0-9]\.[0-9]*\.[0-9]*\.[0-9]" -e "[0-9A-Fa-f]*:[0-9A-Fa-f]*:" {} + 2>/dev/null |
            awk "$1" | head -n 20000' sh "$_IP_AWK"
    section carving.log_ips sh -c '
        [ -d /var/log ] || exit 0
        find /var/log -xdev -path /var/log/journal -prune -o -type f -size -1024k \
            -exec grep -IEHn -e "[0-9]\.[0-9]*\.[0-9]*\.[0-9]" -e "[0-9A-Fa-f]*:[0-9A-Fa-f]*:" \
            {} + 2>/dev/null | awk "$1" | head -n 20000' sh "$_IP_AWK"
    section carving.etc_names sh -c '
        find /etc -xdev -type f -perm -0004 -size -1024k -exec grep -IEHn \
            -e "[a-zA-Z0-9-]\.[a-zA-Z0-9-]*\.[a-zA-Z]" {} + 2>/dev/null |
            awk "$1" | head -n 5000' sh "$_FQDN_AWK"
    if [ -d /run/systemd/system ] && have journalctl; then
        # Only "COUNT ADDRESS|PREFIX|BEFORE|AFTER|FLAGS", never the messages.
        section carving.journal_ips sh -c '
            journalctl --since -7d -o cat --no-pager -q 2>/dev/null | head -n 200000 |
                sed "s/^/journal:0:/" | awk "$1" | cut -d"|" -f3- | sort | uniq -c |
                sort -rn | head -n 5000' sh "$_IP_AWK"
    else
        _empty carving.journal_ips "kind=cmd tool=journalctl" na "systemd is not running"
    fi
}

collect_neighbours() {
    # 3.17 Neighbours (passive): the ARP and NDP tables the kernel already has.
    section_file neighbours.proc_arp /proc/net/arp
    section neighbours.ip_neigh ip neigh show
}

main() {
    bundle_begin
    collect_meta
    collect_system
    collect_hardware
    collect_packages
    collect_storage
    collect_permissions
    collect_identity
    collect_users
    collect_services
    collect_network
    collect_firewall
    collect_timesync
    collect_processes
    collect_load
    collect_sessions
    collect_carving
    collect_neighbours
    bundle_end
}

# ARIDI_COLLECT_LIB=1 only defines the functions (used by tests/collector/).
if [ "${ARIDI_COLLECT_LIB:-}" != 1 ]; then
    main
    exit 0
fi
