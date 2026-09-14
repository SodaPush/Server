# SodaPush Server

SodaPush Server is the API backend for the [SodaPush](https://github.com/SodaPush/SodaPush) self-hosted Apple Push Notification service. Deploy the same Hono application on Cloudflare Workers with D1/Queues or on Node.js/Docker with SQLite. Operators use [SodaPush Admin](https://github.com/SodaPush/AdminClient-Swift); receiving apps use [SodaPush SDK](https://github.com/SodaPush/SDK-Swift).

## Capabilities

- Encrypted APNs keys, SDK registration secrets, and device tokens
- Separate development (APNs sandbox) and production devices and credentials
- Environment-specific default APNs keys plus per-push key selection
- Device registration with platform metadata, preferred language, tags, and business user ID
- Audience targeting by all active devices, installation IDs, tags, languages, or user IDs
- Alert, background, Live Activity, and custom APNs payloads
- Delivery history, result inspection, and deletion of completed push records
- One immutable instance owner plus admin/developer/viewer roles and per-app membership

## Requirements

- Node.js 20+
- pnpm 11
- Cloudflare for Workers deployment, or Docker/Node.js for self-hosting
- Apple Team ID, APNs Key ID, and `.p8` signing key
- Random 32-byte base64url `MASTER_KEY`
- Long one-time `BOOTSTRAP_TOKEN`

Never commit the two secrets. Losing `MASTER_KEY` makes encrypted records unreadable.

## Install and verify

```sh
pnpm install --frozen-lockfile
pnpm check
```

## Cloudflare deployment

```sh
pnpm exec wrangler login
pnpm exec wrangler d1 create sodapush-db
pnpm exec wrangler queues create sodapush-pushes
pnpm exec wrangler queues create sodapush-pushes-dlq
```

Put the D1 UUID in `wrangler.jsonc`. Create an uncommitted `.env.production`:

```dotenv
MASTER_KEY=<32-byte-base64url-key>
BOOTSTRAP_TOKEN=<long-random-token>
```

Then apply migrations and deploy:

```sh
pnpm run deploy:production
curl https://<worker-host>/readyz
```

## Docker or Node.js deployment

```sh
cp .env.example .env
docker compose up --build -d
curl http://127.0.0.1:8787/readyz
```

The Docker volume stores SQLite data. Back it up together with `MASTER_KEY`, and place a TLS reverse proxy in front of port 8787 in production. Node startup applies all migrations automatically.

## Provisioning

Bootstrap exactly once:

```sh
curl -X POST 'https://<server>/v1/bootstrap' \
  -H 'Content-Type: application/json' \
  -H 'X-Soda-Bootstrap-Token: <bootstrap-token>' \
  --data '{"username":"owner","password":"replace-with-a-long-password"}'
```

Create an app with the returned bearer token. The response contains an SDK registration secret shown only once:

```sh
curl -X POST 'https://<server>/v1/apps' \
  -H 'Authorization: Bearer <access-token>' \
  -H 'Content-Type: application/json' \
  --data '{"name":"Example App","bundleID":"com.example.app"}'
```

Upload an environment-specific APNs key:

```sh
curl -X POST 'https://<server>/v1/apps/<app-id>/apns-credentials' \
  -H 'Authorization: Bearer <access-token>' \
  -H 'Content-Type: application/json' \
  --data-binary '{"teamID":"<team-id>","keyID":"<key-id>","p8":"<private-key-pem>","environment":"production","makeDefault":true}'
```

Use a JSON-aware tool for multiline PEM content.

## Push targeting

`POST /v1/apps/:appID/pushes` requires an environment, payload, and exactly one audience selector. `credentialID` is optional; omitting it uses the environment default.

```json
{
  "environment": "production",
  "credentialID": "optional-credential-id",
  "pushType": "alert",
  "target": { "tags": ["paid", "beta"] },
  "payload": { "aps": { "alert": { "title": "Hello", "body": "Welcome back" } } }
}
```

Supported targets are `{ "all": true }`, `installationIds`, `tags`, `languages`, or `userIDs`. Multiple values within a selector use OR matching. Only active devices in the selected environment are eligible.

## API summary

- Health/setup: `GET /healthz`, `GET /readyz`, `GET /v1/bootstrap/status`, `POST /v1/bootstrap`
- Authentication: `POST /v1/auth/login`, `POST /v1/auth/logout`, `GET /v1/me`
- Apps: `GET|POST /v1/apps`, `GET|PATCH /v1/apps/:appID`
- APNs credentials: `GET|POST /v1/apps/:appID/apns-credentials`, `PATCH|DELETE /v1/apps/:appID/apns-credentials/:credentialID`
- Registration keys: `GET|POST /v1/apps/:appID/registration-keys`, `DELETE /v1/apps/:appID/registration-keys/:keyID`
- Devices: `GET /v1/apps/:appID/devices`, signed `PUT|DELETE /v1/apps/:appID/devices/:installationID`
- Pushes: `GET|POST /v1/apps/:appID/pushes`, `GET|DELETE /v1/apps/:appID/pushes/:jobID`
- Users/members: `GET|POST /v1/users`, `PATCH /v1/users/:userID`, `GET /v1/apps/:appID/members`, `PUT|DELETE /v1/apps/:appID/members/:userID`

SDK registration requests use `X-Soda-Key-ID`, `X-Soda-Timestamp`, `X-Soda-Nonce`, and `X-Soda-Signature`. The HMAC-SHA256 input covers method, canonical target, timestamp, nonce, and body hash.

## Security notes

- The owner is created only by bootstrap and cannot be added, disabled, demoted, or removed.
- `.p8` material is never returned after upload; registration secrets are returned only once.
- Successful deliveries are not repeated during queue retries, though a narrow crash window remains between APNs acceptance and persistence.
- An SDK registration key embedded in an app is rotatable authorization, not device attestation.

## Layout

- `src/index.ts`: routes, authorization, registration, targeting, and queue processing
- `src/apns.ts`: APNs authentication and delivery
- `src/auth.ts`, `src/crypto.ts`: sessions and cryptography
- `src/node.ts`: Node.js/libSQL adapter
- `migrations/`: D1/SQLite schema
- `test/`: API, schema, and security tests
