#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "bootstrap must run as root" >&2
    exit 1
fi

if [[ ! -s /root/.ssh/authorized_keys ]]; then
    echo "refusing to disable password authentication without an SSH key" >&2
    exit 1
fi

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get -y upgrade
apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    fail2ban \
    openssl \
    sqlite3 \
    ufw \
    unattended-upgrades

if ! swapon --show=NAME --noheadings | grep -q .; then
    fallocate -l 2G /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=2048 status=progress
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
fi

if ! grep -q '^/swapfile ' /etc/fstab; then
    printf '%s\n' '/swapfile none swap sw 0 0' >> /etc/fstab
fi

install -m 0644 /dev/null /etc/sysctl.d/99-nl-auth.conf
cat > /etc/sysctl.d/99-nl-auth.conf <<'EOF'
vm.swappiness = 10
vm.vfs_cache_pressure = 50
net.ipv4.tcp_syncookies = 1
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
EOF
sysctl --system >/dev/null

rm -f /etc/ssh/sshd_config.d/99-nl-auth-hardening.conf
install -m 0644 /dev/null /etc/ssh/sshd_config.d/00-nl-auth-hardening.conf
cat > /etc/ssh/sshd_config.d/00-nl-auth-hardening.conf <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
PermitRootLogin prohibit-password
PubkeyAuthentication yes
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
GatewayPorts no
PermitUserEnvironment no
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
EOF
/usr/sbin/sshd -t
systemctl reload ssh

ufw default deny incoming
ufw default allow outgoing
ufw allow OpenSSH
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

install -m 0644 /dev/null /etc/fail2ban/jail.d/sshd.local
cat > /etc/fail2ban/jail.d/sshd.local <<'EOF'
[sshd]
enabled = true
backend = systemd
maxretry = 4
findtime = 10m
bantime = 1h
EOF
systemctl enable --now fail2ban

dpkg-reconfigure -f noninteractive unattended-upgrades
systemctl enable --now unattended-upgrades

if ! id -u nl-auth >/dev/null 2>&1; then
    useradd --system --home-dir /var/lib/nl-auth --create-home --shell /usr/sbin/nologin nl-auth
fi

install -d -o root -g root -m 0755 /opt/nl-auth
install -d -o root -g nl-auth -m 0750 /etc/nl-auth
install -d -o nl-auth -g nl-auth -m 0750 /var/lib/nl-auth
install -d -o nl-auth -g nl-auth -m 0750 /var/lib/nl-auth/artifacts

echo "bootstrap complete"
ufw status verbose
free -h
df -h /
