#!/usr/bin/env bash
# Recover the existing InfluxDB setup token for a local thesis vCPE.
# Stores it in a private .env file; never prints the token.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT_DIR/.env"

if [[ -f "$ENV_FILE" ]] && grep -Eq '^INFLUX_TOKEN=.+$' "$ENV_FILE"; then
    echo "An INFLUX_TOKEN already exists in .env; leaving it unchanged."
    exit 0
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: docker is not installed or not on PATH." >&2
    exit 1
fi

if ! docker inspect influxdb >/dev/null 2>&1; then
    echo "ERROR: no 'influxdb' container found or Docker access denied." >&2
    echo "Run on the existing CPE-A as a user with Docker access." >&2
    exit 1
fi

# Official InfluxDB 2 Docker bootstrap config. No secrets go to the console.
TOKEN="$(docker exec influxdb cat /etc/influxdb2/influx-configs 2>/dev/null \
    | awk -F '"' '/^[[:space:]]*token[[:space:]]*=/ { print $2; exit }' \
    || true)"

if [[ -z "$TOKEN" ]]; then
    echo "ERROR: no token was found in /etc/influxdb2/influx-configs." >&2
    echo "This CPE may have been configured without a persistent bootstrap CLI config." >&2
    echo "A valid token must then be obtained from the existing InfluxDB administrator." >&2
    echo "Do not generate an arbitrary new token for an already initialized database." >&2
    exit 1
fi

umask 077
TMP_FILE="$(mktemp "$ROOT_DIR/.env.tmp.XXXXXX")"
trap 'rm -f "$TMP_FILE"' EXIT

if [[ -f "$ENV_FILE" ]]; then
    # Preserve other environment variables but replace any blank token entry.
    grep -v '^INFLUX_TOKEN=' "$ENV_FILE" > "$TMP_FILE" || true
fi
printf 'INFLUX_TOKEN=%s\n' "$TOKEN" >> "$TMP_FILE"
mv "$TMP_FILE" "$ENV_FILE"
chmod 600 "$ENV_FILE"
trap - EXIT
unset TOKEN

echo "Existing InfluxDB token stored locally in .env (not printed)."
echo "Next: docker compose up -d --no-deps --force-recreate vcpe-monitoring"
