#!/bin/sh
# Reference facts of a corpus sample (TODO.md, phase 1.1). Runs as root INSIDE the same
# disposable container right after the collector, and prints the "ground truth" obtained
# with the system's own tools. Parser tests compare their results with this file.
#
# Output: blocks "### <name>" followed by the content, or by "(missing: <tool>)".
# Like the collector, it never prints password hashes: only the algorithm prefix.

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
export PATH LC_ALL

have() { command -v "$1" >/dev/null 2>&1; }

block() {
    # block NAME TOOL COMMAND...: runs COMMAND if TOOL exists.
    name=$1
    tool=$2
    shift 2
    echo "### $name"
    if [ "$tool" = "-" ] || have "$tool"; then
        "$@" 2>&1
    else
        echo "(missing: $tool)"
    fi
}

cat_if() { [ -r "$1" ] && cat "$1" || echo "(missing: $1)"; }

hash_prefixes() {
    # user:prefix, where prefix is "$id$", "!", "!!", "*", "" or "other"; never the hash.
    awk -F: '{
        p = $2
        if (p ~ /^\$/) { split(p, a, "$"); p = "$" a[2] "$" }
        else if (p ~ /^!+\$/) { split(p, a, "$"); p = "!$" a[2] "$" }
        else if (p != "" && p != "!" && p != "!!" && p != "*" && p != "!*") { p = "other" }
        print $1 ":" p
    }' /etc/shadow
}

packages() {
    if have dpkg-query; then
        dpkg-query -W -f '${db:Status-Abbrev}\t${binary:Package}\t${Version}\t${Architecture}\n' | awk '$1 == "ii"' | cut -f2-
    elif have rpm; then
        rpm -qa --qf '%{NAME}\t%{EPOCH}:%{VERSION}-%{RELEASE}\t%{ARCH}\n' | sort
    elif have apk; then
        apk info -v 2>/dev/null | sort
    elif have pacman; then
        pacman -Q
    else
        echo "(missing: package manager)"
    fi
}

block os_release - cat_if /etc/os-release
block kernel uname uname -a
block libc - sh -c 'ldd --version 2>&1 | head -1; ls /lib/ld-musl-* 2>/dev/null'
block arch uname uname -m
block cpu_count - sh -c 'grep -c ^processor /proc/cpuinfo'
block meminfo - sh -c 'head -3 /proc/meminfo'
block packages - packages
echo "### packages_count"
packages | grep -vc '^(missing'
block passwd - cat /etc/passwd
block group - cat /etc/group
block shadow_prefixes - hash_prefixes
block listening ss ss -lntup
block listening_netstat netstat netstat -lntup
block proc_net_tcp6_listen - sh -c "awk 'NR > 1 && \$4 == \"0A\" {print \$2}' /proc/net/tcp6 2>/dev/null"
block proc_net_udp_unconnected - sh -c "awk 'NR > 1 && \$4 == \"07\" {print \$2}' /proc/net/udp 2>/dev/null"
block links_ip ip ip -o link
block interfaces_ip ip ip -o addr
block interfaces_sys - sh -c 'for i in /sys/class/net/*; do echo "${i##*/} $(cat "$i/address" 2>/dev/null)"; done'
block mountinfo - cat /proc/self/mountinfo
block df df df -P -k
block suid_files find sh -c 'find / -xdev -type f -perm -4000 2>/dev/null | sort'
block sgid_files find sh -c 'find / -xdev -type f -perm -2000 2>/dev/null | sort'
block world_writable_dirs_no_sticky find sh -c 'find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null | sort'
block account_file_modes - sh -c 'ls -ln /etc/passwd /etc/group /etc/shadow /etc/gshadow 2>&1'
block processes ps ps -eo pid,uid,stat,comm
block process_count - sh -c 'ls -d /proc/[0-9]* | wc -l'
block hostname - cat_if /proc/sys/kernel/hostname
block resolv_conf - cat_if /etc/resolv.conf
block hosts - cat_if /etc/hosts
block systemd - sh -c '[ -d /run/systemd/system ] && echo running || echo "not running"'
block services_systemctl systemctl systemctl list-units --all --plain --no-legend --no-pager
block services_openrc rc-status rc-status -a
block services_chkconfig chkconfig chkconfig --list
block nft nft nft list ruleset
block iptables iptables-save iptables-save
