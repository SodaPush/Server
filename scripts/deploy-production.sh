#!/usr/bin/env bash
set -euo pipefail

secrets_file=".env.production"

if [[ ! -f "$secrets_file" ]]; then
  echo "Missing $secrets_file. Copy .env.example and set MASTER_KEY and BOOTSTRAP_TOKEN." >&2
  exit 1
fi

for secret_name in MASTER_KEY BOOTSTRAP_TOKEN; do
  if ! grep -Eq "^${secret_name}=[^[:space:]]+" "$secrets_file"; then
    echo "$secret_name is missing or empty in $secrets_file." >&2
    exit 1
  fi
done

echo "Applying production D1 migrations..."
pnpm exec wrangler d1 migrations apply SODAPUSH_DB --remote

echo "Deploying SodaPush Worker..."
pnpm exec wrangler deploy --secrets-file "$secrets_file"
