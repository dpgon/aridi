#!/bin/sh
# VM part of the corpus scenario (TODO.md, phase 1.2). Runs as root INSIDE a disposable
# Lima VM, after "aridi-scenario.sh static" (tests/corpus/scenario.sh). Adds what only a
# full machine has: systemd units, real SSH sessions, firewall rules and time sync.
# Prints "ok|skip <what>" lines, like scenario.sh.

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

have() { command -v "$1" >/dev/null 2>&1; }
ok() { echo "ok $*"; }
skip() { echo "skip $*"; }

# Listeners and the uid-without-account process, as transient systemd units. A unit is
# "ok" only if it is still active a moment later (systemd-run returns 0 on start).
started() { sleep 1; systemctl is-active --quiet "$1"; }
for spec in "tcp6-any 8080" "tcp4-local 8081" "udp4-any 5514"; do
    set -- $spec
    if systemd-run --quiet --unit "aridi-listen-$2" sh /usr/local/sbin/aridi-scenario.sh listen "$1" "$2" &&
        started "aridi-listen-$2"; then
        ok "listener $spec (systemd unit aridi-listen-$2)"
    else
        skip "listener $spec"
    fi
done
# systemd's User= fails for a uid without account, so the unit runs as root and drops
# privileges with setpriv (util-linux).
if have setpriv &&
    systemd-run --quiet --unit aridi-uid4242 setpriv --reuid=4242 --regid=4242 --clear-groups sleep 3600 &&
    started aridi-uid4242; then
    ok "process with uid 4242 without account (systemd unit aridi-uid4242, setpriv)"
else
    skip "process with uid 4242"
fi

# A service that fails on purpose.
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

# Real SSH sessions: one finished and one still open (wtmp/utmp or wtmpdb), and a
# failed attempt for an unknown user (journald; btmp needs a password prompt, which
# cannot be automated without extra tools).
systemctl enable --now ssh 2>/dev/null || systemctl enable --now sshd 2>/dev/null
mkdir -p /root/.ssh /home/alice/.ssh
[ -f /root/.ssh/id_ed25519 ] || ssh-keygen -q -t ed25519 -N '' -f /root/.ssh/id_ed25519
cat /root/.ssh/id_ed25519.pub > /home/alice/.ssh/authorized_keys
chown -R alice: /home/alice/.ssh
chmod 700 /home/alice/.ssh
chmod 600 /home/alice/.ssh/authorized_keys
# -n: ssh must never read stdin (this script may be fed through "sh -s").
sshopts="-n -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"
if ssh $sshopts alice@127.0.0.1 true && ssh $sshopts -6 alice@::1 true; then
    ok "finished ssh sessions of alice from 127.0.0.1 and ::1"
else
    skip "finished ssh sessions of alice"
fi
# The open session must not keep this script's stdout open, or the caller waits for it.
if ssh $sshopts -f alice@127.0.0.1 sleep 3600 >/dev/null 2>&1; then
    ok "open ssh session of alice (sleep 3600)"
else
    skip "open ssh session of alice"
fi
ssh $sshopts nosuchuser@127.0.0.1 true 2>/dev/null
ok "failed ssh attempt for nosuchuser (journald)"

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
else
    skip "nftables"
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
    systemctl restart chronyd 2>/dev/null
    ok "chrony server 192.0.2.124"
fi

skip "btrfs subvolume (the Lima images use ext4/xfs)"
skip "USB devices (none in a VM)"
