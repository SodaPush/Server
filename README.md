# SodaPush Server

SodaPush Server is the API-only backend for SodaPush. It registers Apple device
tokens, stores APNs credentials, accepts push jobs, and records delivery results.
There is no bundled web interface.

The same API supports two deployment models:

- Cloudflare Workers with D1 and Queues
- Self-hosted Node.js or Docker with SQLite/libSQL

Operators use
[SodaPush-Client_Swift](https://github.com/guoPhineas/SodaPush-Client_Swift)
for day-to-day access. Business applications register devices through
[SodaPush-SDK_Swift](https://github.com/guoPhineas/SodaPush-SDK_Swift).

## Requirements

- Node.js 20 or later
- pnpm 11
- A Cloudflare account for the Workers deployment, or Docker/Node.js for self-hosting
- An Apple Developer Team ID, APNs Key ID, and `.p8` provider key
- A random 32-byte base64url `MASTER_KEY`
- A long, one-time `BOOTSTRAP_TOKEN`

Never commit either secret. `MASTER_KEY` encrypts APNs private keys,
registration secrets, and device tokens at rest. Losing or changing it makes
existing encrypted records unreadable.

## API

Health and setup:

- `GET /healthz`
- `GET /readyz`
- `GET /v1/bootstrap/status`
- `POST /v1/bootstrap`

Management API, authenticated with `Authorization: Bearer <access-token>`:

- `POST /v1/auth/login`
- `GET /v1/me`
- `GET /v1/apps`
- `POST /v1/apps`
- `POST /v1/apps/:appID/apns-credential`
- `GET /v1/apps/:appID/devices`
- `POST /v1/apps/:appID/pushes`

SDK API, authenticated with signed request headers:

- `PUT /v1/apps/:appID/devices/:installationID`
- `DELETE /v1/apps/:appID/devices/:installationID?environment=<environment>`

Public JSON uses camelCase. SDK requests include `X-Soda-Key-ID`,
`X-Soda-Timestamp`, `X-Soda-Nonce`, and `X-Soda-Signature`. The signature is
HMAC-SHA256 over the method, canonical target, timestamp, nonce, and SHA-256
body hash. For `DELETE`, the canonical target includes the `environment` query.

## Install and verify

```sh
pnpm install --frozen-lockfile
pnpm check
```

Tests cover the schema, security primitives, bootstrap, app creation, public
response casing, signed registration, and environment-scoped unregistration.

For local Worker development, create an uncommitted `.dev.vars`:

```dotenv
MASTER_KEY=<32-byte-base64url-key>
BOOTSTRAP_TOKEN=<long-random-token>
```

Then run:

```sh
pnpm run db:migrate:local
pnpm run dev
```

## Deploy to Cloudflare

Authenticate and create the backing resources:

```sh
pnpm exec wrangler login
pnpm exec wrangler d1 create sodapush-db
pnpm exec wrangler queues create sodapush-pushes
pnpm exec wrangler queues create sodapush-pushes-dlq
```

Copy the D1 UUID returned by the first resource command into `database_id` in
`wrangler.jsonc`. The Queue names must continue to match that file.

Apply the production schema:

```sh
pnpm run db:migrate:remote
```

Create an uncommitted `.env.production` containing both required secrets:

```dotenv
MASTER_KEY=<32-byte-base64url-key>
BOOTSTRAP_TOKEN=<long-random-token>
```

Upload the secrets together with the Worker and verify readiness:

```sh
pnpm exec wrangler deploy --secrets-file .env.production
curl https://<worker-host>/readyz
```

The deployed Worker produces and consumes `sodapush-pushes`; exhausted retries
are routed to `sodapush-pushes-dlq`. Configure a custom domain or Worker route
after deployment if desired.

## Deploy with Docker or Node.js

Copy the provided environment template and replace every placeholder:

```sh
cp .env.example .env
docker compose up --build -d
curl http://127.0.0.1:8787/readyz
```

The SQLite database is stored in the `sodapush-data` Docker volume. Back up this
volume together with `MASTER_KEY`. Put a TLS reverse proxy in front of port 8787
for production because the management client and SDK require HTTPS.

To run Node.js without Docker:

```sh
PORT=8787 \
MASTER_KEY='<32-byte-base64url-key>' \
BOOTSTRAP_TOKEN='<long-random-token>' \
pnpm run start:node
```

Node startup applies the idempotent schema. Since Cloudflare Queues are not
available in this runtime, accepted push jobs are processed inline.

## First-time provisioning

Bootstrap exactly once:

```sh
curl -X POST 'https://<server>/v1/bootstrap' \
  -H 'Content-Type: application/json' \
  -H 'X-Soda-Bootstrap-Token: <bootstrap-token>' \
  --data '{"username":"owner","password":"replace-with-a-long-password"}'
```

Save the returned `accessToken`, then create an application:

```sh
curl -X POST 'https://<server>/v1/apps' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <access-token>' \
  --data '{"name":"Example App","bundleID":"com.example.app"}'
```

The response contains a registration key secret that is shown only once. Store
its `app.id`, `registrationKey.keyID`, and `registrationKey.secret` in the
business application's deployment configuration.

Upload the APNs provider credential:

```sh
curl -X POST 'https://<server>/v1/apps/<app-id>/apns-credential' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <access-token>' \
  --data-binary '{"teamID":"<team-id>","keyID":"<apns-key-id>","p8":"<private-key-pem>"}'
```

For multiline `.p8` data, generate the JSON body with a JSON-aware tool rather
than manually escaping the PEM contents.

## Security and reliability notes

- APNs keys, registration secrets, and device tokens are AES-GCM encrypted.
- Device-token hashes are stored separately for uniqueness checks.
- Registration nonces expire and are removed during later signed requests.
- Per-app membership is checked before accessing app resources.
- An SDK registration credential is extractable from a sufficiently analyzed
  application. Rotate it when necessary and add attestation if stronger device
  authenticity is required.
- Push processing avoids repeating recorded successful deliveries, but there is
  still a narrow crash window between APNs acceptance and the database update.

## Repository layout

- `src/index.ts`: routes, authorization, registration, push processing, and Worker entry points
- `src/auth.ts`: password hashing and expiring bearer sessions
- `src/crypto.ts`: encryption, hashing, HMAC, base64url, and request IDs
- `src/apns.ts`: APNs provider-token creation and delivery
- `src/node.ts`: Node.js and libSQL runtime adapter
- `migrations/`: D1/SQLite-compatible schema
- `test/`: schema, security, and API contract tests
- `wrangler.jsonc`: Worker, D1, Queue, and required-secret bindings
- `Dockerfile` and `docker-compose.yml`: self-hosted container runtime
