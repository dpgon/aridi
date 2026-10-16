# SSH target of the integration test (TODO.md 5.4): Debian 12 with OpenSSH and sudo.
# tests/central/run.sh installs the collector and the sudo rule of TODO.md 5.0 at run
# time, so the image never holds a key or a script.
FROM debian:12
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server sudo \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd \
 && useradd -m -s /bin/sh aridi && useradd -m -s /bin/sh nosudo \
 && printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\n' \
      > /etc/ssh/sshd_config.d/aridi-test.conf
CMD ["/usr/sbin/sshd", "-D", "-e"]
