#!/usr/bin/env bash
set -Eeuo pipefail

SOURCE_DIR=${1:-/root/nl-auth-source/server}
SERVICE_FILE=${2:-/root/nl-auth-source/deploy/nl-auth.service}
BOOTSTRAP_USERNAME=${NL_AUTH_BOOTSTRAP_USERNAME:-admin}

if [[ ! ${BOOTSTRAP_USERNAME} =~ ^[A-Za-z0-9_.-]{3,32}$ ]]; then
    echo "invalid bootstrap username" >&2
    exit 1
fi

if [[ ${EUID} -ne 0 ]]; then
    echo "installer must run as root" >&2
    exit 1
fi
if [[ ! -f "${SOURCE_DIR}/go.mod" || ! -f "${SERVICE_FILE}" ]]; then
    echo "source or service file is missing" >&2
    exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends golang-go

if ! id -u nl-auth >/dev/null 2>&1; then
    useradd --system --home-dir /var/lib/nl-auth --create-home --shell /usr/sbin/nologin nl-auth
fi
install -d -o root -g root -m 0755 /opt/nl-auth
install -d -o root -g root -m 0755 /opt/nl-auth/loader-template
install -d -o root -g nl-auth -m 0750 /etc/nl-auth
install -d -o nl-auth -g nl-auth -m 0750 /var/lib/nl-auth /var/lib/nl-auth/artifacts

if [[ ! -f /etc/nl-auth/signing-key.pem ]]; then
    openssl ecparam -name prime256v1 -genkey -noout -out /etc/nl-auth/signing-key.pem
fi
chown root:nl-auth /etc/nl-auth/signing-key.pem
chmod 0640 /etc/nl-auth/signing-key.pem

if [[ ! -f /etc/nl-auth/nl-auth.env ]]; then
    pepper=$(openssl rand -base64 32 | tr -d '\n')
    artifact_key=$(openssl rand -base64 32 | tr -d '\n')
    cat > /etc/nl-auth/nl-auth.env <<EOF
NL_AUTH_LISTEN=127.0.0.1:8080
NL_AUTH_DB=/var/lib/nl-auth/auth.db
NL_AUTH_ARTIFACT_DIR=/var/lib/nl-auth/artifacts
NL_AUTH_SIGNING_KEY=/etc/nl-auth/signing-key.pem
NL_AUTH_PUBLIC_URL=http://127.0.0.1:8080
NL_AUTH_SESSION_TTL=15m
NL_AUTH_DOWNLOAD_TTL=60s
NL_AUTH_LOADER_DOWNLOAD_TTL=5m
NL_AUTH_MAX_ARTIFACT_BYTES=268435456
NL_AUTH_LOADER_TEMPLATE=/opt/nl-auth/loader-template/nl-loader.exe
NL_AUTH_PEPPER=${pepper}
NL_AUTH_ARTIFACT_KEY=${artifact_key}
NL_AUTH_DISCORD_PUBLIC_KEY=
NL_AUTH_DISCORD_ADMIN_ROLE_ID=
NL_AUTH_DISCORD_APPLICATION_ID=
NL_AUTH_DISCORD_GUILD_ID=
NL_AUTH_DISCORD_BOT_TOKEN=
NL_AUTH_DISCORD_BOT_TOKEN_FILE=/etc/nl-auth/discord-bot-token
NL_AUTH_DISCORD_SECURITY_CHANNEL_ID=
EOF
fi
if ! grep -q '^NL_AUTH_LOADER_DOWNLOAD_TTL=' /etc/nl-auth/nl-auth.env; then
    printf '%s\n' 'NL_AUTH_LOADER_DOWNLOAD_TTL=5m' >> /etc/nl-auth/nl-auth.env
fi
if ! grep -q '^NL_AUTH_LOADER_TEMPLATE=' /etc/nl-auth/nl-auth.env; then
    printf '%s\n' 'NL_AUTH_LOADER_TEMPLATE=/opt/nl-auth/loader-template/nl-loader.exe' >> /etc/nl-auth/nl-auth.env
fi
if ! grep -q '^NL_AUTH_DISCORD_SECURITY_CHANNEL_ID=' /etc/nl-auth/nl-auth.env; then
    printf '%s\n' 'NL_AUTH_DISCORD_SECURITY_CHANNEL_ID=' >> /etc/nl-auth/nl-auth.env
fi
if ! grep -q '^NL_AUTH_DISCORD_BOT_TOKEN_FILE=' /etc/nl-auth/nl-auth.env; then
    printf '%s\n' 'NL_AUTH_DISCORD_BOT_TOKEN_FILE=/etc/nl-auth/discord-bot-token' >> /etc/nl-auth/nl-auth.env
fi
chown root:nl-auth /etc/nl-auth/nl-auth.env
chmod 0640 /etc/nl-auth/nl-auth.env

pushd "${SOURCE_DIR}" >/dev/null
export GOMAXPROCS=1
export GOMEMLIMIT=700MiB
go mod tidy
go test ./...
go build -trimpath -ldflags='-s -w -buildid=' -o /tmp/nl-auth ./cmd/nl-auth
popd >/dev/null
install -o root -g root -m 0755 /tmp/nl-auth /opt/nl-auth/nl-auth
rm -f /tmp/nl-auth

install -o root -g root -m 0644 "${SERVICE_FILE}" /etc/systemd/system/nl-auth.service
systemctl daemon-reload

set -a
source /etc/nl-auth/nl-auth.env
set +a
export HOME=/var/lib/nl-auth
runuser -u nl-auth --preserve-environment -- /opt/nl-auth/nl-auth public-key >/dev/null

admin_count=$(sqlite3 /var/lib/nl-auth/auth.db "SELECT COUNT(1) FROM accounts WHERE role='admin';")
if [[ ${admin_count} -eq 0 ]]; then
    admin_password=$(openssl rand -base64 24 | tr -d '\n')
    export NL_AUTH_BOOTSTRAP_PASSWORD=${admin_password}
    runuser -u nl-auth --preserve-environment -- /opt/nl-auth/nl-auth bootstrap-admin --username "${BOOTSTRAP_USERNAME}"
    unset NL_AUTH_BOOTSTRAP_PASSWORD
    umask 077
    printf 'username=%s\npassword=%s\n' "${BOOTSTRAP_USERNAME}" "${admin_password}" > /root/nl-auth-initial-admin.txt
fi
chown nl-auth:nl-auth /var/lib/nl-auth/auth.db
chmod 0600 /var/lib/nl-auth/auth.db
find /var/lib/nl-auth -maxdepth 1 -type f \( -name 'auth.db-wal' -o -name 'auth.db-shm' \) -exec chown nl-auth:nl-auth {} + -exec chmod 0600 {} +

systemctl enable nl-auth
if systemctl is-active --quiet nl-auth; then
    systemctl restart nl-auth
else
    systemctl start nl-auth
fi
for attempt in {1..20}; do
    if curl --fail --silent http://127.0.0.1:8080/healthz >/dev/null; then
        break
    fi
    sleep 1
done
curl --fail --silent http://127.0.0.1:8080/healthz
echo
systemctl --no-pager --full status nl-auth | sed -n '1,18p'
