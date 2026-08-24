#!/usr/bin/env bash
set -Eeuo pipefail

ENV_FILE=${NL_AUTH_ENV_FILE:-/etc/nl-auth/nl-auth.env}
TOKEN_FILE=${NL_AUTH_DISCORD_TOKEN_FILE:-/etc/nl-auth/discord-bot-token}
AUTH_BINARY=${NL_AUTH_BINARY:-/opt/nl-auth/nl-auth}

if [[ ${EUID} -ne 0 ]]; then
    echo "registration must run as root" >&2
    exit 1
fi
if [[ ! -r "${ENV_FILE}" || ! -x "${AUTH_BINARY}" ]]; then
    echo "nl-auth is not installed" >&2
    exit 1
fi

if [[ ${1:-} == "--stored" ]]; then
    if [[ ! -r "${TOKEN_FILE}" ]]; then
        echo "stored Discord token is unavailable" >&2
        exit 1
    fi
    token=$(<"${TOKEN_FILE}")
else
    read -r -s -p "Discord bot token: " token
    printf '\n'
fi
token=${token%$'\r'}

if [[ ${#token} -lt 40 || ${#token} -gt 256 || ${token} == *[[:space:]]* ]]; then
    unset token
    echo "Discord bot token has an invalid format" >&2
    exit 1
fi

set -a
# shellcheck disable=SC1090
source "${ENV_FILE}"
set +a
export NL_AUTH_DISCORD_BOT_TOKEN=${token}
export HOME=/var/lib/nl-auth

if ! runuser -u nl-auth --preserve-environment -- "${AUTH_BINARY}" discord-register; then
    unset NL_AUTH_DISCORD_BOT_TOKEN token
    echo "Discord rejected the token or application configuration" >&2
    exit 1
fi

if [[ ${1:-} != "--stored" ]]; then
    old_umask=$(umask)
    umask 077
    printf '%s' "${token}" > "${TOKEN_FILE}"
    umask "${old_umask}"
fi
chown root:nl-auth "${TOKEN_FILE}"
chmod 0640 "${TOKEN_FILE}"

unset NL_AUTH_DISCORD_BOT_TOKEN token
echo "Discord commands registered"
