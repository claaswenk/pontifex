#!/bin/sh
# Creates .env from .env.example with a random value for every empty secret.
# Refuses to overwrite an existing .env, so running secrets are never replaced.

set -eu

cd "$(dirname "$0")/.."

if [ -e .env ]; then
    echo "[ERROR] .env already exists. Delete it first if you really want new secrets." >&2
    exit 1
fi

umask 077
: > .env

while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
        INITIAL_API_KEY=|JWT_SECRET=|BACKEND_FRONTEND_SECRET=|BACKEND_DATABASE_SECRET=)
            printf '%s%s\n' "$line" "$(openssl rand -hex 32)" >> .env
            ;;
        *)
            printf '%s\n' "$line" >> .env
            ;;
    esac
done < .env.example

echo "[OK] .env created. Next: podman compose up -d"
echo "[INFO] INITIAL_API_KEY is needed once to create the first admin:"
grep '^INITIAL_API_KEY=' .env
