#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
umask 077

command -v pnpm >/dev/null || { echo "pnpm is required." >&2; exit 1; }
command -v node >/dev/null || { echo "Node.js is required." >&2; exit 1; }
command -v openssl >/dev/null || { echo "OpenSSL is required." >&2; exit 1; }

secrets_file=".env.production"
if [[ ! -f "$secrets_file" ]]; then
  master_key="$(openssl rand -base64 32 | tr '/+' '_-' | tr -d '=\n')"
  printf 'MASTER_KEY=%s\n' "$master_key" > "$secrets_file"
  echo "Generated MASTER_KEY in $secrets_file. Keep this file backed up; losing the key makes encrypted data unreadable."
elif ! grep -Eq '^MASTER_KEY=[A-Za-z0-9_-]{43}$' "$secrets_file"; then
  echo "Existing $secrets_file has no valid MASTER_KEY. Restore the original key; it will not be rotated automatically." >&2
  exit 1
fi

if ! grep -Eq '^BOOTSTRAP_TOKEN=[^[:space:]]{20,}$' "$secrets_file"; then
  if [[ ! -t 0 ]]; then
    echo "BOOTSTRAP_TOKEN is missing. Run interactively or add it to $secrets_file (20+ characters)." >&2
    exit 1
  fi
  read -r -s -p "Choose a BOOTSTRAP_TOKEN (20+ characters, no spaces): " bootstrap_token
  echo
  if [[ ${#bootstrap_token} -lt 20 || "$bootstrap_token" =~ [[:space:]] ]]; then
    echo "BOOTSTRAP_TOKEN must be at least 20 characters with no whitespace." >&2
    exit 1
  fi
  printf 'BOOTSTRAP_TOKEN=%s\n' "$bootstrap_token" >> "$secrets_file"
fi
chmod 600 "$secrets_file"

echo "Checking Cloudflare authentication..."
pnpm exec wrangler whoami

database_name="$(node scripts/cloudflare-resources.mjs database-name)"
database_id="$(pnpm exec wrangler d1 list --json | node scripts/cloudflare-resources.mjs lookup-d1 "$database_name")"
if [[ -z "$database_id" ]]; then
  echo "Creating D1 database $database_name..."
  pnpm exec wrangler d1 create "$database_name"
  database_id="$(pnpm exec wrangler d1 list --json | node scripts/cloudflare-resources.mjs lookup-d1 "$database_name")"
fi
if [[ -z "$database_id" ]]; then
  echo "Could not resolve the D1 database ID." >&2
  exit 1
fi
node scripts/cloudflare-resources.mjs configure-d1 "$database_id"

for queue_name in $(node scripts/cloudflare-resources.mjs queue-names); do
  if ! pnpm exec wrangler queues list | node scripts/cloudflare-resources.mjs has-queue "$queue_name"; then
    echo "Creating queue $queue_name..."
    pnpm exec wrangler queues create "$queue_name"
  fi
done

echo "Applying production D1 migrations..."
pnpm exec wrangler d1 migrations apply SODAPUSH_DB --remote

echo "Deploying SodaPush Worker..."
pnpm exec wrangler deploy --secrets-file "$secrets_file"
