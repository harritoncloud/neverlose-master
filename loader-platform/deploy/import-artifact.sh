#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "import must run as root" >&2
    exit 1
fi
if [[ $# -ne 2 ]]; then
    echo "usage: import-artifact.sh <version> <platform>" >&2
    exit 1
fi

set -a
source /etc/nl-auth/nl-auth.env
set +a
export HOME=/var/lib/nl-auth
export GOMEMLIMIT=512MiB
runuser -u nl-auth --preserve-environment -- \
    /opt/nl-auth/nl-auth artifact-import --file - --version "$1" --platform "$2"
