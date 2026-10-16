#!/bin/sh
# Test scenario of the corpus (TODO.md, phase 1.1). Runs as root INSIDE a disposable
# container, never on a real machine. It reproduces the cases that broke the 2019 aridi
# (docs/MVP.md), so every raw bundle of the corpus contains them.
#
# Usage (from tests/corpus/capture.sh):
#   scenario.sh static              users, groups, files, banners, hosts, carving data
#   scenario.sh listen KIND PORT    exec a listener: KIND = tcp6-any | tcp4-local | udp4-any
#
# Every action prints one line "ok|skip <what> [reason]" so the capture keeps a record of
# what the sample really contains.

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

have() { command -v "$1" >/dev/null 2>&1; }
ok() { echo "ok $*"; }
skip() { echo "skip $*"; }

add_user() {
    # add_user NAME UID
    if have useradd; then
        useradd -m -u "$2" -s /bin/sh "$1"
    elif have adduser; then
        adduser -D -u "$2" -s /bin/sh "$1"
    else
        return 1
    fi
}

static() {
    # alice: account with a password, hashed with the distribution's default algorithm
    # (yescrypt on current Debian, Ubuntu and Fedora).
    if add_user alice 2001 && echo 'alice:Corpus-Pass-2026' | chpasswd; then
        ok "user alice with password (default algorithm)"
    else
        skip "user alice (no useradd/adduser/chpasswd)"
    fi

    # bob: locked account.
    if add_user bob 2002; then
        if have usermod && usermod -L bob 2>/dev/null; then
            ok "user bob locked (usermod -L)"
        elif have passwd && passwd -l bob >/dev/null 2>&1; then
            ok "user bob locked (passwd -l)"
        else
            skip "lock bob (no usermod/passwd -l)"
        fi
    else
        skip "user bob"
    fi

    # A group whose member has no local account (broke 2019 gathering2.py:112).
    echo "ghostgrp:x:4300:ghostuser,alice" >> /etc/group
    [ -f /etc/gshadow ] && echo "ghostgrp:!::ghostuser,alice" >> /etc/gshadow
    ok "group ghostgrp with member without account (ghostuser)"

    # Dangerous permissions: a SUID copy of true and a world-writable dir without sticky.
    mkdir -p /usr/local/bin /srv
    true_bin=""
    for candidate in /bin/true /usr/bin/true /bin/busybox; do
        if [ -x "$candidate" ]; then true_bin=$candidate; break; fi
    done
    if [ -n "$true_bin" ] && cp "$true_bin" /usr/local/bin/aridi-suid-test; then
        chmod 4755 /usr/local/bin/aridi-suid-test
        ok "suid file /usr/local/bin/aridi-suid-test (copy of $true_bin)"
    else
        skip "suid file (no true binary)"
    fi
    mkdir -p /srv/world-writable && chmod 0777 /srv/world-writable
    ok "world-writable dir without sticky bit /srv/world-writable"

    # Untrusted banner content: ANSI escape and HTML.
    printf 'Corpus banner \033[31mred\033[0m <script>alert(1)</script>\n' > /etc/issue.net
    ok "banner /etc/issue.net with ANSI and <script>"

    # Name resolution data: extra hosts (v4 and v6) and an IPv6 DNS server.
    printf '10.20.30.40 corpus-db.example.internal\n2001:db8::40 corpus-db6.example.internal\n' >> /etc/hosts
    echo "nameserver 2001:db8::53" >> /etc/resolv.conf
    ok "hosts entries v4/v6 and IPv6 nameserver"

    # Carving data: IPs mixed with versions and network prefixes.
    cat > /etc/aridi-corpus.conf <<'EOF'
# aridi corpus: carving test data
server 192.0.2.10
backup_server 2001:db8::10
version 1.2.3.4
allowed_network 198.51.100.0/24
monitor 203.0.113.7/32
link_local 169.254.10.20
EOF
    mkdir -p /var/log
    cat > /var/log/aridi-corpus.log <<'EOF'
2026-10-01T10:00:00Z sshd[100]: Failed password for root from 203.0.113.50 port 50000 ssh2
2026-10-01T10:00:05Z sshd[101]: Accepted publickey for alice from 2001:db8::77 port 50001 ssh2
EOF
    ok "carving data /etc/aridi-corpus.conf and /var/log/aridi-corpus.log"
}

listen() {
    # listen KIND PORT: replaces this shell with a long-running listener.
    kind=$1
    port=$2
    if have socat; then
        case $kind in
            tcp6-any)   exec socat -u "TCP6-LISTEN:$port,reuseaddr,fork,ipv6only=0" OPEN:/dev/null ;;
            tcp4-local) exec socat -u "TCP4-LISTEN:$port,bind=127.0.0.1,reuseaddr,fork" OPEN:/dev/null ;;
            udp4-any)   exec socat -u "UDP4-RECV:$port,bind=0.0.0.0" OPEN:/dev/null ;;
        esac
    fi
    if have python3; then
        case $kind in
            tcp6-any)   fam=AF_INET6; typ=SOCK_STREAM; addr="::" ;;
            tcp4-local) fam=AF_INET;  typ=SOCK_STREAM; addr="127.0.0.1" ;;
            udp4-any)   fam=AF_INET;  typ=SOCK_DGRAM;  addr="0.0.0.0" ;;
        esac
        exec python3 -c "
import socket, time
s = socket.socket(socket.$fam, socket.$typ)
s.bind(('$addr', $port))
if socket.$typ == socket.SOCK_STREAM:
    s.listen()
time.sleep(86400)"
    fi
    if have nc && ! nc --help 2>&1 | grep -qi busybox; then
        # Traditional/OpenBSD nc (CentOS 6 "nc" package): one connection per run, so loop.
        case $kind in
            tcp6-any)   exec sh -c "while :; do nc -6 -l $port < /dev/null; done" ;;
            tcp4-local) exec sh -c "while :; do nc -l 127.0.0.1 $port < /dev/null; done" ;;
            udp4-any)   exec sh -c "while :; do nc -u -l $port < /dev/null; done" ;;
        esac
    fi
    if have busybox && busybox nc --help 2>&1 | grep -q -- '-l'; then
        case $kind in
            tcp4-local) exec busybox nc -lk -s 127.0.0.1 -p "$port" ;;
            *) ;;
        esac
    fi
    exit 3
}

case ${1:-} in
    static) static ;;
    listen) listen "$2" "$3" ;;
    *) echo "usage: $0 static | listen KIND PORT" >&2; exit 2 ;;
esac
