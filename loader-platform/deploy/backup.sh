#!/usr/bin/env bash
set -Eeuo pipefail

backup_root=/var/backups/nl-auth
timestamp=$(date -u +%Y%m%dT%H%M%SZ)
destination=${backup_root}/${timestamp}

install -d -o root -g root -m 0700 "${backup_root}" "${destination}"
sqlite3 /var/lib/nl-auth/auth.db ".timeout 10000" ".backup '${destination}/auth.db'"
cp -a /etc/nl-auth "${destination}/config"
sha256sum "${destination}/auth.db" > "${destination}/SHA256SUMS"
chmod -R go-rwx "${destination}"

mapfile -t old_backups < <(find "${backup_root}" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' | sort -rn | awk 'NR > 7 {print $2}')
for old_backup in "${old_backups[@]}"; do
    [[ "${old_backup}" == "${backup_root}/"* ]] || exit 1
    rm -rf -- "${old_backup}"
done
