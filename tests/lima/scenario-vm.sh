#!/bin/sh
# VM part of the corpus scenario (TODO.md, phase 1.2). Runs as root INSIDE a disposable
# VM (Lima; plain QEMU for CentOS 6 and 7), after "aridi-scenario.sh static"
# (tests/corpus/scenario.sh). Adds what only a full machine has: an init system, real
# SSH sessions, firewall rules and time sync.
# Prints "ok|skip <what>" lines, like scenario.sh.

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

have() { command -v "$1" >/dev/null 2>&1; }
ok() { echo "ok $*"; }
skip() { echo "skip $*"; }

# Listeners and the uid-without-account process. With systemd, as transient units; a unit
# is "ok" only if it is still active a moment later (systemd-run returns 0 on start).
# Without systemd (CentOS 6), as detached processes, "ok" if still alive a moment later.
if have systemd-run && [ -d /run/systemd/system ]; then
    systemd=yes
else
    systemd=no
fi
started() { sleep 1; systemctl is-active --quiet "$1"; }
detach() {
    # detach CMD...: runs CMD in its own session, with no terminal and closed stdio.
    setsid "$@" < /dev/null > /dev/null 2>&1 &
    pid=$!
    sleep 1
    kill -0 "$pid" 2>/dev/null
}
for spec in "tcp6-any 8080" "tcp4-local 8081" "udp4-any 5514"; do
    set -- $spec
    if [ "$systemd" = yes ]; then
        if systemd-run --quiet --unit "aridi-listen-$2" sh /usr/local/sbin/aridi-scenario.sh listen "$1" "$2" &&
            started "aridi-listen-$2"; then
            ok "listener $spec (systemd unit aridi-listen-$2)"
        else
            skip "listener $spec"
        fi
    elif detach sh /usr/local/sbin/aridi-scenario.sh listen "$1" "$2"; then
        ok "listener $spec (detached process)"
    else
        skip "listener $spec"
    fi
done
# systemd's User= fails for a uid without account, so the unit runs as root and drops
# privileges with setpriv (util-linux). util-linux of CentOS 6 has no setpriv: python 2
# drops them instead.
uid4242="import os, time; os.setgroups([]); os.setgid(4242); os.setuid(4242); time.sleep(3600)"
if [ "$systemd" = yes ] && have setpriv &&
    systemd-run --quiet --unit aridi-uid4242 setpriv --reuid=4242 --regid=4242 --clear-groups sleep 3600 &&
    started aridi-uid4242; then
    ok "process with uid 4242 without account (systemd unit aridi-uid4242, setpriv)"
elif [ "$systemd" = no ] && have setpriv &&
    detach setpriv --reuid=4242 --regid=4242 --clear-groups sleep 3600; then
    ok "process with uid 4242 without account (detached, setpriv)"
elif [ "$systemd" = no ] && have python && detach python -c "$uid4242"; then
    ok "process with uid 4242 without account (detached, python)"
else
    skip "process with uid 4242"
fi

# A service that fails on purpose (SysV init has no "failed" state).
if [ "$systemd" = yes ]; then
    cat > /etc/systemd/system/aridi-fails.service <<'EOF'
[Unit]
Description=aridi corpus: service that fails on purpose

[Service]
Type=oneshot
ExecStart=/bin/false
EOF
    systemctl daemon-reload
    systemctl start aridi-fails.service 2>/dev/null
    if systemctl is-failed --quiet aridi-fails.service; then
        ok "failed service aridi-fails.service"
    else
        skip "failed service aridi-fails.service"
    fi
else
    skip "failed service (no systemd)"
fi

# Real SSH sessions: one finished and one still open (wtmp/utmp or wtmpdb), and a
# failed attempt for an unknown user (journald; btmp needs a password prompt, which
# cannot be automated without extra tools).
systemctl enable --now ssh 2>/dev/null || systemctl enable --now sshd 2>/dev/null ||
    service sshd start > /dev/null 2>&1
mkdir -p /root/.ssh /home/alice/.ssh
# OpenSSH 5.3 (CentOS 6) has no ed25519: RSA there.
key=/root/.ssh/id_ed25519
[ -f $key ] || ssh-keygen -q -t ed25519 -N '' -f $key 2>/dev/null || {
    key=/root/.ssh/id_rsa
    [ -f $key ] || ssh-keygen -q -t rsa -b 3072 -N '' -f $key
}
cat $key.pub > /home/alice/.ssh/authorized_keys
chown -R alice: /home/alice/.ssh
chmod 700 /home/alice/.ssh
chmod 600 /home/alice/.ssh/authorized_keys
# -n: ssh must never read stdin (this script may be fed through "sh -s").
sshopts="-n -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"
# -tt: sshd records a session in utmp/wtmp only when it has a terminal.
if ssh $sshopts -tt alice@127.0.0.1 true && ssh $sshopts -tt -6 alice@::1 true; then
    ok "finished ssh sessions of alice from 127.0.0.1 and ::1"
else
    skip "finished ssh sessions of alice"
fi
# The open session must not keep this script's stdout open, or the caller waits for it.
if ssh $sshopts -tt -f alice@127.0.0.1 sleep 3600 >/dev/null 2>&1; then
    ok "open ssh session of alice (sleep 3600)"
else
    skip "open ssh session of alice"
fi
ssh $sshopts nosuchuser@127.0.0.1 true 2>/dev/null
ok "failed ssh attempt for nosuchuser (journald or /var/log/secure)"

# Firewall: a dedicated nftables table with input, output and forward rules.
if have nft; then
    nft -f - <<'EOF'
table inet aridi_corpus {
    chain input {
        type filter hook input priority 10; policy accept;
        ip saddr 192.0.2.10 tcp dport 22 accept
        ip6 saddr 2001:db8::10 tcp dport 22 accept
    }
    chain output {
        type filter hook output priority 10; policy accept;
        ip daddr 198.51.100.5 tcp dport 443 accept
    }
    chain forward {
        type filter hook forward priority 10; policy drop;
        ip saddr 10.0.0.0/8 accept
    }
}
EOF
    ok "nftables table inet aridi_corpus (input/output/forward)"
elif have iptables; then
    # Same rules with iptables (CentOS 6 and 7, without nft). Input only accepts, so the
    # SSH of the capture is never cut.
    iptables -A INPUT -s 192.0.2.10/32 -p tcp --dport 22 -j ACCEPT &&
        iptables -A OUTPUT -d 198.51.100.5/32 -p tcp --dport 443 -j ACCEPT &&
        iptables -P FORWARD DROP &&
        iptables -A FORWARD -s 10.0.0.0/8 -j ACCEPT &&
        ok "iptables rules in INPUT/OUTPUT/FORWARD (filter)" || skip "iptables rules"
    if have ip6tables; then
        ip6tables -A INPUT -s 2001:db8::10/128 -p tcp --dport 22 -j ACCEPT &&
            ok "ip6tables rule in INPUT (filter)" || skip "ip6tables rule"
    fi
else
    skip "nftables or iptables"
fi
if have firewall-cmd; then
    firewall-cmd -q --add-rich-rule='rule family=ipv4 source address=192.0.2.20/32 port port=8443 protocol=tcp accept' &&
        ok "firewalld rich rule 192.0.2.20 -> 8443/tcp" || skip "firewalld rich rule"
fi

# Time sync configuration pointing to fixed names (no resolution needed).
if [ -f /etc/systemd/timesyncd.conf ]; then
    mkdir -p /etc/systemd/timesyncd.conf.d
    printf '[Time]\nNTP=ntp1.example.org 192.0.2.123\n' > /etc/systemd/timesyncd.conf.d/aridi.conf
    systemctl restart systemd-timesyncd 2>/dev/null
    ok "timesyncd servers ntp1.example.org 192.0.2.123"
fi
if [ -f /etc/chrony.conf ]; then
    echo "server 192.0.2.124 iburst" >> /etc/chrony.conf
    systemctl restart chronyd 2>/dev/null || service chronyd restart > /dev/null 2>&1
    ok "chrony server 192.0.2.124"
elif [ -f /etc/ntp.conf ]; then
    echo "server 192.0.2.125 iburst" >> /etc/ntp.conf
    service ntpd restart > /dev/null 2>&1
    ok "ntpd server 192.0.2.125"
fi

skip "btrfs subvolume (the Lima images use ext4/xfs)"
skip "USB devices (none in a VM)"
