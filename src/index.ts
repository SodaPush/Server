import { Hono } from "hono";
import type { Context } from "hono";
import { decryptSecret, encryptSecret, hmacSha256Base64Url, randomRequestID, sha256Base64Url, constantTimeEqual } from "./crypto";
import { createSession, getSessionUser, hashPassword, randomToken, verifyPassword } from "./auth";
import { sendToAPNs } from "./apns";
import type { DeviceRegistrationRequest, Env, ErrorBody, SessionUser } from "./types";

type AppContext = Context<{ Bindings: Env }>;
type AppRole = "owner" | "admin" | "developer" | "viewer";
interface PushMessage { jobID: string }

interface AppRecord {
  id: string;
  name: string;
  bundle_id: string;
  created_at: string;
  disabled_at: string | null;
}

export const app = new Hono<{ Bindings: Env }>();

function errorResponse(c: AppContext, status: number, code: string, message: string) {
  const requestId = randomRequestID();
  const body: ErrorBody = { code, message, requestId };
  return c.json(body, status as never, { "X-Request-ID": requestId });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function validString(value: unknown, max: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= max;
}

async function jsonBody(c: AppContext, maxBytes: number): Promise<unknown | Response> {
  const raw = await c.req.text();
  if (new TextEncoder().encode(raw).byteLength > maxBytes) return errorResponse(c, 413, "request_too_large", "Request body is too large");
  try { return JSON.parse(raw) as unknown; }
  catch { return errorResponse(c, 400, "invalid_json", "Request body must be valid JSON"); }
}

async function requireUser(c: AppContext): Promise<SessionUser | Response> {
  const user = await getSessionUser(c.req.raw, c.env);
  return user ?? errorResponse(c, 401, "unauthorized", "Authentication is required");
}

async function appRole(env: Env, user: SessionUser, appID: string): Promise<AppRole | null> {
  if (user.role === "owner") return "owner";
  const row = await env.SODAPUSH_DB.prepare("SELECT role FROM app_memberships WHERE app_id = ?1 AND user_id = ?2 LIMIT 1").bind(appID, user.id).first<{ role: AppRole }>();
  return row?.role ?? null;
}

function hasRole(role: AppRole | null, allowed: AppRole[]): boolean { return role !== null && allowed.includes(role); }

function appDTO(row: AppRecord, role: AppRole) {
  return { id: row.id, name: row.name, bundleID: row.bundle_id, role, createdAt: row.created_at, disabledAt: row.disabled_at };
}

async function findApp(env: Env, appID: string): Promise<AppRecord | null> {
  return env.SODAPUSH_DB.prepare("SELECT id,name,bundle_id,created_at,disabled_at FROM apps WHERE id=?1 LIMIT 1").bind(appID).first<AppRecord>();
}

function hasOnlyKeys(value: Record<string, unknown>, allowed: string[]): boolean {
  return Object.keys(value).every((key) => allowed.includes(key));
}

function parsedPushRequest(value: string): Record<string, unknown> | null {
  try {
    const parsed = JSON.parse(value) as unknown;
    return isRecord(parsed) ? parsed : null;
  } catch { return null; }
}

type PushEnvironment = "development" | "production";

function validEnvironment(value: unknown): value is PushEnvironment {
  return value === "development" || value === "production";
}

function normalizedStringList(value: unknown, maximumCount = 50): string[] | null {
  if (!Array.isArray(value) || value.length === 0 || value.length > maximumCount || !value.every((item) => validString(item, 128))) return null;
  const normalized = [...new Set(value.map((item) => item.trim()).filter(Boolean))];
  return normalized.length > 0 ? normalized : null;
}

function credentialDTO(row: { id: string; team_id: string; key_id: string; environment: string; is_default: number; created_at: string; updated_at: string }) {
  return { id: row.id, teamID: row.team_id, keyID: row.key_id, environment: row.environment, isDefault: row.is_default === 1, createdAt: row.created_at, updatedAt: row.updated_at };
}

app.get("/healthz", (c) => c.json({ status: "ok", version: c.env.APP_VERSION ?? "unknown" }));
app.get("/readyz", async (c) => {
  try {
    await c.env.SODAPUSH_DB.prepare("SELECT key FROM instance_settings LIMIT 1").first();
    await encryptSecret(c.env.MASTER_KEY, "readiness-check");
    return c.json({ status: "ready" });
  } catch { return c.json({ status: "not_ready" }, 503); }
});

app.get("/v1/bootstrap/status", async (c) => {
  const setting = await c.env.SODAPUSH_DB.prepare("SELECT value FROM instance_settings WHERE key = 'initialized'").first<{ value: string }>();
  return c.json({ initialized: setting?.value === "true" });
});

app.post("/v1/bootstrap", async (c) => {
  const setting = await c.env.SODAPUSH_DB.prepare("SELECT value FROM instance_settings WHERE key = 'initialized'").first<{ value: string }>();
  if (setting?.value === "true") return errorResponse(c, 409, "already_initialized", "The instance is already initialized");
  const bootstrapSecret = c.req.header("X-Soda-Bootstrap-Token");
  if (!bootstrapSecret || !c.env.BOOTSTRAP_TOKEN || !constantTimeEqual(bootstrapSecret, c.env.BOOTSTRAP_TOKEN)) return errorResponse(c, 401, "invalid_bootstrap_token", "Bootstrap token is invalid");
  const parsed = await jsonBody(c, 16 * 1024);
  if (parsed instanceof Response) return parsed;
  if (!isRecord(parsed) || !validString(parsed.username, 64) || !/^[A-Za-z0-9_.-]{3,64}$/.test(parsed.username) || !validString(parsed.password, 1024) || parsed.password.length < 12) return errorResponse(c, 400, "invalid_owner", "Username or password does not meet the minimum requirements");
  const password = await hashPassword(parsed.password);
  const userID = crypto.randomUUID();
  const now = new Date().toISOString();
  await c.env.SODAPUSH_DB.batch([
    c.env.SODAPUSH_DB.prepare("INSERT INTO users (id, username, password_hash, password_salt, role, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, 'owner', ?5, ?5)").bind(userID, parsed.username, password.hash, password.salt, now),
    c.env.SODAPUSH_DB.prepare("INSERT INTO instance_settings (key, value) VALUES ('initialized', 'true')"),
  ]);
  const accessToken = await createSession(c.env, userID);
  return c.json({ user: { id: userID, username: parsed.username, role: "owner" }, accessToken }, 201);
});

app.post("/v1/auth/login", async (c) => {
  const parsed = await jsonBody(c, 16 * 1024);
  if (parsed instanceof Response) return parsed;
  if (!isRecord(parsed) || !validString(parsed.username, 64) || !validString(parsed.password, 1024)) return errorResponse(c, 400, "invalid_credentials", "Username and password are required");
  const user = await c.env.SODAPUSH_DB.prepare("SELECT id, username, role, password_hash, password_salt FROM users WHERE username = ?1 AND disabled_at IS NULL LIMIT 1").bind(parsed.username).first<{ id: string; username: string; role: AppRole; password_hash: string; password_salt: string }>();
  if (!user || !(await verifyPassword(parsed.password, user.password_hash, user.password_salt))) return errorResponse(c, 401, "invalid_credentials", "Username or password is incorrect");
  const accessToken = await createSession(c.env, user.id);
  return c.json({ user: { id: user.id, username: user.username, role: user.role }, accessToken });
});

app.post("/v1/auth/logout", async (c) => {
  const user = await requireUser(c);
  if (user instanceof Response) return user;
  const token = c.req.header("Authorization")?.slice(7).trim();
  if (!token) return errorResponse(c, 401, "unauthorized", "Authentication is required");
  await c.env.SODAPUSH_DB.prepare("UPDATE sessions SET revoked_at=?1 WHERE token_hash=?2 AND revoked_at IS NULL").bind(Math.floor(Date.now() / 1000), await sha256Base64Url(token)).run();
  return c.body(null, 204);
});

app.get("/v1/me", async (c) => {
  const user = await requireUser(c);
  return user instanceof Response ? user : c.json({ user });
});

app.get("/v1/apps", async (c) => {
  const user = await requireUser(c);
  if (user instanceof Response) return user;
  const query = user.role === "owner"
    ? "SELECT id, name, bundle_id, created_at, disabled_at, 'owner' AS effective_role FROM apps ORDER BY created_at DESC"
    : `SELECT apps.id, apps.name, apps.bundle_id, apps.created_at, apps.disabled_at, app_memberships.role AS effective_role FROM apps JOIN app_memberships ON app_memberships.app_id = apps.id WHERE app_memberships.user_id = ?1 ORDER BY apps.created_at DESC`;
  const statement = c.env.SODAPUSH_DB.prepare(query);
  const rows = await (user.role === "owner" ? statement : statement.bind(user.id)).all<AppRecord & { effective_role: AppRole }>();
  return c.json({ apps: rows.results.map((row) => appDTO(row, row.effective_role)) });
});

app.post("/v1/apps", async (c) => {
  const user = await requireUser(c);
  if (user instanceof Response) return user;
  if (user.role !== "owner" && user.role !== "admin") return errorResponse(c, 403, "forbidden", "App management permission is required");
  const parsed = await jsonBody(c, 16 * 1024);
  if (parsed instanceof Response) return parsed;
  if (!isRecord(parsed) || !validString(parsed.name, 128) || !validString(parsed.bundleID, 255) || !/^[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)+$/.test(parsed.bundleID)) return errorResponse(c, 400, "invalid_app", "A valid name and bundleID are required");
  const appID = crypto.randomUUID();
  const registrationKeyID = crypto.randomUUID();
  const keyID = `reg_${randomToken(8)}`;
  const registrationSecret = randomToken(32);
  const encrypted = await encryptSecret(c.env.MASTER_KEY, registrationSecret);
  const now = new Date().toISOString();
  await c.env.SODAPUSH_DB.batch([
    c.env.SODAPUSH_DB.prepare("INSERT INTO apps (id, name, bundle_id, created_at) VALUES (?1, ?2, ?3, ?4)").bind(appID, parsed.name, parsed.bundleID, now),
    c.env.SODAPUSH_DB.prepare("INSERT INTO app_memberships (user_id, app_id, role, created_at) VALUES (?1, ?2, 'owner', ?3)").bind(user.id, appID, now),
    c.env.SODAPUSH_DB.prepare("INSERT INTO registration_keys (id, app_id, key_id, secret_ciphertext, secret_nonce, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)").bind(registrationKeyID, appID, keyID, encrypted.ciphertext, encrypted.nonce, now),
  ]);
  return c.json({ app: { id: appID, name: parsed.name, bundleID: parsed.bundleID, role: "owner", createdAt: now, disabledAt: null }, registrationKey: { id: registrationKeyID, keyID, secret: registrationSecret, active: true, createdAt: now, revokedAt: null } }, 201);
});

app.get("/v1/apps/:appID", async (c) => {
  const user = await requireUser(c);
  if (user instanceof Response) return user;
  const appID = c.req.param("appID"), role = await appRole(c.env, user, appID);
  if (!hasRole(role, ["owner", "admin", "developer", "viewer"])) return errorResponse(c, 403, "forbidden", "App access is required");
  const record = await findApp(c.env, appID);
  if (!record) return errorResponse(c, 404, "app_not_found", "App was not found");
  return c.json({ app: appDTO(record, role!) });
});

app.post("/v1/apps/:appID/update", async (c) => {
  const user = await requireUser(c);
  if (user instanceof Response) return user;
  const appID = c.req.param("appID"), role = await appRole(c.env, user, appID);
  if (!hasRole(role, ["owner", "admin"])) return errorResponse(c, 403, "forbidden", "App management permission is required");
  const existing = await findApp(c.env, appID);
  if (!existing) return errorResponse(c, 404, "app_not_found", "App was not found");
  const parsed = await jsonBody(c, 16 * 1024);
  if (parsed instanceof Response) return parsed;
  if (!isRecord(parsed) || !hasOnlyKeys(parsed, ["name", "disabled"]) || Object.keys(parsed).length === 0 || (parsed.name !== undefined && !validString(parsed.name, 128)) || (parsed.disabled !== undefined && typeof parsed.disabled !== "boolean")) return errorResponse(c, 400, "invalid_app", "name or disabled must be valid");
  const name = typeof parsed.name === "string" ? parsed.name : existing.name;
  const disabledAt = parsed.disabled === undefined ? existing.disabled_at : parsed.disabled ? new Date().toISOString() : null;
  await c.env.SODAPUSH_DB.prepare("UPDATE apps SET name=?1,disabled_at=?2 WHERE id=?3").bind(name, disabledAt, appID).run();
  return c.json({ app: appDTO({ ...existing, name, disabled_at: disabledAt }, role!) });
});

async function createAPNsCredential(c: AppContext, legacyResponse = false) {
  const user = await requireUser(c);
  if (user instanceof Response) return user;
  const appID = c.req.param("appID") ?? "";
  if (!hasRole(await appRole(c.env, user, appID), ["owner", "admin"])) return errorResponse(c, 403, "forbidden", "APNs credential management permission is required");
  if (!await findApp(c.env, appID)) return errorResponse(c, 404, "app_not_found", "App was not found");
  const parsed = await jsonBody(c, 40 * 1024);
  if (parsed instanceof Response) return parsed;
  if (!isRecord(parsed) || !validString(parsed.teamID, 32) || !validString(parsed.keyID, 32) || !validString(parsed.p8, 32_000) || !parsed.p8.includes("PRIVATE KEY") || (parsed.environment !== undefined && !validEnvironment(parsed.environment)) || (parsed.makeDefault !== undefined && typeof parsed.makeDefault !== "boolean")) return errorResponse(c, 400, "invalid_credential", "teamID, keyID, environment and a valid p8 are required");
  const encrypted = await encryptSecret(c.env.MASTER_KEY, parsed.p8);
  const credentialID = crypto.randomUUID();
  const now = new Date().toISOString();
  const environment = validEnvironment(parsed.environment) ? parsed.environment : "production";
  const existingDefault = await c.env.SODAPUSH_DB.prepare("SELECT id FROM apns_credentials WHERE app_id=?1 AND environment=?2 AND is_default=1 LIMIT 1").bind(appID, environment).first<{ id: string }>();
  const makeDefault = parsed.makeDefault === true || !existingDefault;
  const statements = [];
  if (makeDefault) statements.push(c.env.SODAPUSH_DB.prepare("UPDATE apns_credentials SET is_default=0 WHERE app_id=?1 AND environment=?2").bind(appID, environment));
  statements.push(c.env.SODAPUSH_DB.prepare(`INSERT INTO apns_credentials (id, app_id, team_id, key_id, p8_ciphertext, p8_nonce, environment, is_default, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9) ON CONFLICT(app_id, key_id) DO UPDATE SET team_id=excluded.team_id,p8_ciphertext=excluded.p8_ciphertext,p8_nonce=excluded.p8_nonce,environment=excluded.environment,is_default=excluded.is_default,updated_at=excluded.updated_at`).bind(credentialID, appID, parsed.teamID, parsed.keyID, encrypted.ciphertext, encrypted.nonce, environment, makeDefault ? 1 : 0, now));
  await c.env.SODAPUSH_DB.batch(statements);
  const stored = await c.env.SODAPUSH_DB.prepare("SELECT id,team_id,key_id,environment,is_default,created_at,updated_at FROM apns_credentials WHERE app_id=?1 AND key_id=?2 LIMIT 1").bind(appID, parsed.keyID).first<{ id: string; team_id: string; key_id: string; environment: string; is_default: number; created_at: string; updated_at: string }>();
  const credential = credentialDTO(stored!);
  return legacyResponse ? c.json({ appID, teamID: credential.teamID, keyID: credential.keyID, updatedAt: credential.updatedAt }) : c.json({ credential });
}

app.post("/v1/apps/:appID/apns-credential", (c) => createAPNsCredential(c, true));
app.post("/v1/apps/:appID/apns-credentials", (c) => createAPNsCredential(c));

app.get("/v1/apps/:appID/apns-credentials", async (c) => {
  const user = await requireUser(c);
  if (user instanceof Response) return user;
  const appID = c.req.param("appID");
  if (!hasRole(await appRole(c.env, user, appID), ["owner", "admin", "developer", "viewer"])) return errorResponse(c, 403, "forbidden", "App access is required");
  const rows = await c.env.SODAPUSH_DB.prepare("SELECT id,team_id,key_id,environment,is_default,created_at,updated_at FROM apns_credentials WHERE app_id=?1 ORDER BY environment ASC,is_default DESC,updated_at DESC").bind(appID).all<{ id: string; team_id: string; key_id: string; environment: string; is_default: number; created_at: string; updated_at: string }>();
  return c.json({ credentials: rows.results.map(credentialDTO) });
});

app.post("/v1/apps/:appID/apns-credentials/:credentialID/default", async (c) => {
  const user = await requireUser(c);
  if (user instanceof Response) return user;
  const appID = c.req.param("appID"), credentialID = c.req.param("credentialID");
  if (!hasRole(await appRole(c.env, user, appID), ["owner", "admin"])) return errorResponse(c, 403, "forbidden", "APNs credential management permission is required");
  const credential = await c.env.SODAPUSH_DB.prepare("SELECT id,team_id,key_id,environment,is_default,created_at,updated_at FROM apns_credentials WHERE app_id=?1 AND id=?2 LIMIT 1").bind(appID, credentialID).first<{ id: string; team_id: string; key_id: string; environment: string; is_default: number; created_at: string; updated_at: string }>();
  if (!credential) return errorResponse(c, 404, "credential_not_found", "APNs credential was not found");
  const parsed = await jsonBody(c, 4 * 1024);
  if (parsed instanceof Response) return parsed;
  if (!isRecord(parsed) || !hasOnlyKeys(parsed, ["isDefault"]) || parsed.isDefault !== true) return errorResponse(c, 400, "invalid_credential", "isDefault must be true");
  const updatedAt = new Date().toISOString();
  await c.env.SODAPUSH_DB.batch([
    c.env.SODAPUSH_DB.prepare("UPDATE apns_credentials SET is_default=0 WHERE app_id=?1 AND environment=?2").bind(appID, credential.environment),
    c.env.SODAPUSH_DB.prepare("UPDATE apns_credentials SET is_default=1,updated_at=?1 WHERE app_id=?2 AND id=?3").bind(updatedAt, appID, credentialID),
  ]);
  return c.json({ credential: credentialDTO({ ...credential, is_default: 1, updated_at: updatedAt }) });
});

app.post("/v1/apps/:appID/apns-credentials/:credentialID/delete", async (c) => {
  const user = await requireUser(c);
  if (user instanceof Response) return user;
  const appID = c.req.param("appID");
  if (!hasRole(await appRole(c.env, user, appID), ["owner", "admin"])) return errorResponse(c, 403, "forbidden", "APNs credential management permission is required");
  const credential = await c.env.SODAPUSH_DB.prepare("SELECT id,environment,is_default FROM apns_credentials WHERE app_id=?1 AND id=?2 LIMIT 1").bind(appID, c.req.param("credentialID")).first<{ id: string; environment: string; is_default: number }>();
  if (!credential) return errorResponse(c, 404, "credential_not_found", "APNs credential was not found");
  await c.env.SODAPUSH_DB.prepare("DELETE FROM apns_credentials WHERE app_id=?1 AND id=?2").bind(appID, credential.id).run();
  if (credential.is_default === 1) {
    const replacement = await c.env.SODAPUSH_DB.prepare("SELECT id FROM apns_credentials WHERE app_id=?1 AND environment=?2 ORDER BY updated_at DESC LIMIT 1").bind(appID, credential.environment).first<{ id: string }>();
    if (replacement) await c.env.SODAPUSH_DB.prepare("UPDATE apns_credentials SET is_default=1 WHERE id=?1").bind(replacement.id).run();
  }
  return c.body(null, 204);
});

app.get("/v1/apps/:appID/registration-keys", async (c) => {
  const user = await requireUser(c);
  if (user instanceof Response) return user;
  const appID = c.req.param("appID");
  if (!hasRole(await appRole(c.env, user, appID), ["owner", "admin"])) return errorResponse(c, 403, "forbidden", "Registration key management permission is required");
  const rows = await c.env.SODAPUSH_DB.prepare("SELECT id,key_id,active,created_at,revoked_at FROM registration_keys WHERE app_id=?1 ORDER BY created_at DESC").bind(appID).all<{ id: string; key_id: string; active: number; created_at: string; revoked_at: string | null }>();
  return c.json({ registrationKeys: rows.results.map((row) => ({ id: row.id, keyID: row.key_id, active: row.active === 1, createdAt: row.created_at, revokedAt: row.revoked_at })) });
});

app.post("/v1/apps/:appID/registration-keys", async (c) => {
  const user = await requireUser(c);
  if (user instanceof Response) return user;
  const appID = c.req.param("appID");
  if (!hasRole(await appRole(c.env, user, appID), ["owner", "admin"])) return errorResponse(c, 403, "forbidden", "Registration key management permission is required");
  if (!await findApp(c.env, appID)) return errorResponse(c, 404, "app_not_found", "App was not found");
  const id = crypto.randomUUID(), keyID = `reg_${randomToken(8)}`, secret = randomToken(32), now = new Date().toISOString();
  const encrypted = await encryptSecret(c.env.MASTER_KEY, secret);
  await c.env.SODAPUSH_DB.prepare("INSERT INTO registration_keys (id,app_id,key_id,secret_ciphertext,secret_nonce,created_at) VALUES (?1,?2,?3,?4,?5,?6)").bind(id, appID, keyID, encrypted.ciphertext, encrypted.nonce, now).run();
  return c.json({ registrationKey: { id, keyID, secret, active: true, createdAt: now, revokedAt: null } }, 201);
});

app.post("/v1/apps/:appID/registration-keys/:keyID/revoke", async (c) => {
  const user = await requireUser(c);
  if (user instanceof Response) return user;
  const appID = c.req.param("appID"), keyID = c.req.param("keyID");
  if (!hasRole(await appRole(c.env, user, appID), ["owner", "admin"])) return errorResponse(c, 403, "forbidden", "Registration key management permission is required");
  const key = await c.env.SODAPUSH_DB.prepare("SELECT id FROM registration_keys WHERE app_id=?1 AND key_id=?2 LIMIT 1").bind(appID, keyID).first<{ id: string }>();
  if (!key) return errorResponse(c, 404, "registration_key_not_found", "Registration key was not found");
  await c.env.SODAPUSH_DB.prepare("UPDATE registration_keys SET active=0,revoked_at=?1 WHERE id=?2").bind(new Date().toISOString(), key.id).run();
  return c.body(null, 204);
});

app.get("/v1/apps/:appID/devices", async (c) => {
  const user = await requireUser(c);
  if (user instanceof Response) return user;
  const appID = c.req.param("appID");
  if (!hasRole(await appRole(c.env, user, appID), ["owner", "admin", "developer", "viewer"])) return errorResponse(c, 403, "forbidden", "App access is required");
  const rows = await c.env.SODAPUSH_DB.prepare("SELECT installation_id,environment,platform,app_version,app_build,locale,language,time_zone,user_id,tags_json,status,created_at,updated_at FROM devices WHERE app_id=?1 ORDER BY updated_at DESC LIMIT 500").bind(appID).all<DeviceRow>();
  return c.json({ devices: rows.results.map(deviceDTO) });
});

interface DeviceRow { installation_id: string; environment: string; platform: string; app_version: string | null; app_build: string | null; locale: string | null; language: string | null; time_zone: string | null; user_id: string | null; tags_json: string; status: string; created_at: string; updated_at: string }
function deviceDTO(row: DeviceRow) {
  let tags: string[] = [];
  try { const decoded = JSON.parse(row.tags_json); if (Array.isArray(decoded)) tags = decoded.filter((item): item is string => typeof item === "string"); } catch { /* legacy invalid data is treated as untagged */ }
  return { id: `${row.installation_id}:${row.environment}`, installationID: row.installation_id, environment: row.environment, platform: row.platform, appVersion: row.app_version, appBuild: row.app_build, locale: row.locale, language: row.language, timeZone: row.time_zone, userID: row.user_id, tags, status: row.status, createdAt: row.created_at, updatedAt: row.updated_at };
}

app.post("/v1/apps/:appID/devices/:installationID/deactivate", async (c) => {
  const user = await requireUser(c);
  if (user instanceof Response) return user;
  const appID = c.req.param("appID"), installationID = c.req.param("installationID"), environment = c.req.query("environment");
  if (!hasRole(await appRole(c.env, user, appID), ["owner", "admin"])) return errorResponse(c, 403, "forbidden", "Device management permission is required");
  if (!installationPattern.test(installationID)) return errorResponse(c, 400, "invalid_installation_id", "installationID must be a UUID");
  if (environment !== "development" && environment !== "production") return errorResponse(c, 400, "invalid_environment", "environment query parameter is required");
  const parsed = await jsonBody(c, 16 * 1024);
  if (parsed instanceof Response) return parsed;
  if (!isRecord(parsed) || !hasOnlyKeys(parsed, ["status"]) || parsed.status !== "inactive") return errorResponse(c, 400, "invalid_device", "Only status inactive is supported");
  const existing = await c.env.SODAPUSH_DB.prepare("SELECT installation_id,environment,platform,app_version,app_build,locale,language,time_zone,user_id,tags_json,status,created_at,updated_at FROM devices WHERE app_id=?1 AND installation_id=?2 AND environment=?3 LIMIT 1").bind(appID, installationID, environment).first<DeviceRow>();
  if (!existing) return errorResponse(c, 404, "device_not_found", "Device was not found");
  const updatedAt = new Date().toISOString();
  await c.env.SODAPUSH_DB.prepare("UPDATE devices SET status='inactive',updated_at=?1 WHERE app_id=?2 AND installation_id=?3 AND environment=?4").bind(updatedAt, appID, installationID, environment).run();
  return c.json({ device: deviceDTO({ ...existing, status: "inactive", updated_at: updatedAt }) });
});

app.post("/v1/apps/:appID/pushes", async (c) => {
  const user = await requireUser(c);
  if (user instanceof Response) return user;
  const appID = c.req.param("appID");
  if (!hasRole(await appRole(c.env, user, appID), ["owner", "admin", "developer"])) return errorResponse(c, 403, "forbidden", "Push permission is required");
  const parsed = await jsonBody(c, 16 * 1024);
  if (parsed instanceof Response) return parsed;
  if (!isRecord(parsed) || !validEnvironment(parsed.environment) || (parsed.pushType !== undefined && !["alert", "background", "liveactivity"].includes(String(parsed.pushType))) || !isRecord(parsed.target) || !isRecord(parsed.payload) || (parsed.credentialID !== undefined && !validString(parsed.credentialID, 128))) return errorResponse(c, 400, "invalid_push", "environment, credentialID, target and payload are invalid");
  const installationIds = parsed.target.installationIds;
  const tags = parsed.target.tags === undefined ? undefined : normalizedStringList(parsed.target.tags);
  const languages = parsed.target.languages === undefined ? undefined : normalizedStringList(parsed.target.languages);
  const userIDs = parsed.target.userIDs === undefined ? undefined : normalizedStringList(parsed.target.userIDs);
  const validInstallations = installationIds === undefined ? undefined : normalizedStringList(installationIds, 500);
  const selectorCount = [parsed.target.all === true, validInstallations !== undefined, tags !== undefined, languages !== undefined, userIDs !== undefined].filter(Boolean).length;
  if (selectorCount !== 1) return errorResponse(c, 400, "invalid_target", "target must contain exactly one of all, installationIds, tags, languages, or userIDs");
  if (new TextEncoder().encode(JSON.stringify(parsed.payload)).byteLength > 4096) return errorResponse(c, 413, "payload_too_large", "APNs payload exceeds 4096 bytes");
  if (parsed.credentialID) {
    const credential = await c.env.SODAPUSH_DB.prepare("SELECT id FROM apns_credentials WHERE app_id=?1 AND id=?2 AND environment=?3 LIMIT 1").bind(appID, parsed.credentialID, parsed.environment).first();
    if (!credential) return errorResponse(c, 400, "invalid_credential", "The selected APNs credential does not match this app and environment");
  }
  const target = parsed.target.all === true ? { all: true } : validInstallations ? { installationIds: validInstallations } : tags ? { tags } : languages ? { languages } : { userIDs };
  const requestJSON = JSON.stringify({ environment: parsed.environment, credentialID: parsed.credentialID ?? null, pushType: parsed.pushType ?? "alert", target, payload: parsed.payload });
  const jobID = crypto.randomUUID();
  const now = new Date().toISOString();
  await c.env.SODAPUSH_DB.prepare("INSERT INTO push_jobs (id,app_id,environment,request_json,status,created_by,created_at,updated_at) VALUES (?1,?2,?3,?4,'queued',?5,?6,?6)").bind(jobID, appID, parsed.environment, requestJSON, user.id, now).run();
  if (c.env.PUSH_QUEUE) await c.env.PUSH_QUEUE.send({ jobID }); else await processPushJob(c.env, jobID);
  const state = await c.env.SODAPUSH_DB.prepare("SELECT status FROM push_jobs WHERE id=?1").bind(jobID).first<{ status: string }>();
  return c.json({ jobID, status: state?.status ?? "queued" }, 202);
});

interface PushJobRow {
  id: string; app_id: string; environment: string; request_json: string; status: string;
  total_count: number; success_count: number; failure_count: number; created_by: string | null;
  created_at: string; updated_at: string;
}

function pushJobDTO(row: PushJobRow) {
  const request = parsedPushRequest(row.request_json);
  return { id: row.id, appID: row.app_id, environment: row.environment, credentialID: request?.credentialID ?? null, pushType: request?.pushType ?? null, target: request?.target ?? null, payload: request?.payload ?? null, status: row.status, totalCount: row.total_count, successCount: row.success_count, failureCount: row.failure_count, createdBy: row.created_by, createdAt: row.created_at, updatedAt: row.updated_at };
}

app.get("/v1/apps/:appID/pushes", async (c) => {
  const user = await requireUser(c);
  if (user instanceof Response) return user;
  const appID = c.req.param("appID");
  if (!hasRole(await appRole(c.env, user, appID), ["owner", "admin", "developer", "viewer"])) return errorResponse(c, 403, "forbidden", "App access is required");
  const rows = await c.env.SODAPUSH_DB.prepare("SELECT id,app_id,environment,request_json,status,total_count,success_count,failure_count,created_by,created_at,updated_at FROM push_jobs WHERE app_id=?1 ORDER BY created_at DESC LIMIT 100").bind(appID).all<PushJobRow>();
  return c.json({ pushes: rows.results.map(pushJobDTO) });
});

app.get("/v1/apps/:appID/pushes/:jobID", async (c) => {
  const user = await requireUser(c);
  if (user instanceof Response) return user;
  const appID = c.req.param("appID");
  if (!hasRole(await appRole(c.env, user, appID), ["owner", "admin", "developer", "viewer"])) return errorResponse(c, 403, "forbidden", "App access is required");
  const row = await c.env.SODAPUSH_DB.prepare("SELECT id,app_id,environment,request_json,status,total_count,success_count,failure_count,created_by,created_at,updated_at FROM push_jobs WHERE app_id=?1 AND id=?2 LIMIT 1").bind(appID, c.req.param("jobID")).first<PushJobRow>();
  if (!row) return errorResponse(c, 404, "push_not_found", "Push job was not found");
  const deliveries = await c.env.SODAPUSH_DB.prepare("SELECT id,device_id,apns_id,status,apns_status,reason,created_at,updated_at FROM deliveries WHERE job_id=?1 ORDER BY created_at ASC").bind(row.id).all<{ id: string; device_id: string | null; apns_id: string | null; status: string; apns_status: number | null; reason: string | null; created_at: string; updated_at: string }>();
  return c.json({ push: pushJobDTO(row), deliveries: deliveries.results.map((delivery) => ({ id: delivery.id, deviceID: delivery.device_id, apnsID: delivery.apns_id, status: delivery.status, apnsStatus: delivery.apns_status, reason: delivery.reason, createdAt: delivery.created_at, updatedAt: delivery.updated_at })) });
});

app.post("/v1/apps/:appID/pushes/:jobID/delete", async (c) => {
  const user = await requireUser(c);
  if (user instanceof Response) return user;
  const appID = c.req.param("appID"), jobID = c.req.param("jobID");
  if (!hasRole(await appRole(c.env, user, appID), ["owner", "admin", "developer"])) return errorResponse(c, 403, "forbidden", "Push deletion permission is required");
  const job = await c.env.SODAPUSH_DB.prepare("SELECT status FROM push_jobs WHERE app_id=?1 AND id=?2 LIMIT 1").bind(appID, jobID).first<{ status: string }>();
  if (!job) return errorResponse(c, 404, "push_not_found", "Push job was not found");
  if (job.status === "queued" || job.status === "running") return errorResponse(c, 409, "push_in_progress", "A queued or running push cannot be deleted");
  await c.env.SODAPUSH_DB.batch([
    c.env.SODAPUSH_DB.prepare("DELETE FROM deliveries WHERE job_id=?1").bind(jobID),
    c.env.SODAPUSH_DB.prepare("DELETE FROM push_jobs WHERE app_id=?1 AND id=?2").bind(appID, jobID),
  ]);
  return c.body(null, 204);
});

interface UserRow { id: string; username: string; role: AppRole; disabled_at: string | null; created_at: string; updated_at: string }
function userDTO(row: UserRow) { return { id: row.id, username: row.username, role: row.role, disabledAt: row.disabled_at, createdAt: row.created_at, updatedAt: row.updated_at }; }

app.get("/v1/users", async (c) => {
  const user = await requireUser(c);
  if (user instanceof Response) return user;
  if (user.role !== "owner") return errorResponse(c, 403, "forbidden", "Owner permission is required");
  const rows = await c.env.SODAPUSH_DB.prepare("SELECT id,username,role,disabled_at,created_at,updated_at FROM users ORDER BY created_at ASC").all<UserRow>();
  return c.json({ users: rows.results.map(userDTO) });
});

app.post("/v1/users", async (c) => {
  const user = await requireUser(c);
  if (user instanceof Response) return user;
  if (user.role !== "owner") return errorResponse(c, 403, "forbidden", "Owner permission is required");
  const parsed = await jsonBody(c, 16 * 1024);
  if (parsed instanceof Response) return parsed;
  const roles: AppRole[] = ["admin", "developer", "viewer"];
  if (!isRecord(parsed) || !hasOnlyKeys(parsed, ["username", "password", "role"]) || !validString(parsed.username, 64) || !/^[A-Za-z0-9_.-]{3,64}$/.test(parsed.username) || !validString(parsed.password, 1024) || parsed.password.length < 12 || typeof parsed.role !== "string" || !roles.includes(parsed.role as AppRole)) return errorResponse(c, 400, "invalid_user", "Username, password, or role is invalid");
  if (await c.env.SODAPUSH_DB.prepare("SELECT id FROM users WHERE username=?1 LIMIT 1").bind(parsed.username).first()) return errorResponse(c, 409, "username_exists", "Username is already in use");
  const id = crypto.randomUUID(), password = await hashPassword(parsed.password), now = new Date().toISOString();
  await c.env.SODAPUSH_DB.prepare("INSERT INTO users (id,username,password_hash,password_salt,role,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,?6,?6)").bind(id, parsed.username, password.hash, password.salt, parsed.role, now).run();
  return c.json({ user: { id, username: parsed.username, role: parsed.role, disabledAt: null, createdAt: now, updatedAt: now } }, 201);
});

app.post("/v1/users/:userID/update", async (c) => {
  const user = await requireUser(c);
  if (user instanceof Response) return user;
  const target = await c.env.SODAPUSH_DB.prepare("SELECT id,username,role,disabled_at,created_at,updated_at FROM users WHERE id=?1 LIMIT 1").bind(c.req.param("userID")).first<UserRow>();
  if (!target) return errorResponse(c, 404, "user_not_found", "User was not found");
  const isOwnerActor = user.role === "owner";
  if (!isOwnerActor && target.id !== user.id) return errorResponse(c, 403, "forbidden", "Users may only update their own account");
  const parsed = await jsonBody(c, 16 * 1024);
  if (parsed instanceof Response) return parsed;
  const roles: AppRole[] = ["admin", "developer", "viewer"];
  if (!isRecord(parsed) || !hasOnlyKeys(parsed, ["username", "password", "currentPassword", "role", "disabled"]) || Object.keys(parsed).length === 0 || (parsed.username !== undefined && (!validString(parsed.username, 64) || !/^[A-Za-z0-9_.-]{3,64}$/.test(parsed.username))) || (parsed.password !== undefined && (!validString(parsed.password, 1024) || parsed.password.length < 12)) || (parsed.currentPassword !== undefined && !validString(parsed.currentPassword, 1024)) || (parsed.role !== undefined && (typeof parsed.role !== "string" || !roles.includes(parsed.role as AppRole))) || (parsed.disabled !== undefined && typeof parsed.disabled !== "boolean")) return errorResponse(c, 400, "invalid_user", "username, password, currentPassword, role, or disabled must be valid");
  if (!isOwnerActor && (parsed.role !== undefined || parsed.disabled !== undefined)) return errorResponse(c, 403, "forbidden", "Users cannot change their own role or account status");
  if (target.role === "owner" && (parsed.role !== undefined || parsed.disabled !== undefined)) return errorResponse(c, 409, "owner_immutable", "The owner account cannot be disabled or assigned another role");
  const nextUsername = typeof parsed.username === "string" ? parsed.username : target.username;
  if (nextUsername !== target.username && await c.env.SODAPUSH_DB.prepare("SELECT id FROM users WHERE username=?1 AND id<>?2 LIMIT 1").bind(nextUsername, target.id).first()) return errorResponse(c, 409, "username_exists", "Username is already in use");
  const nextRole = (parsed.role as AppRole | undefined) ?? target.role;
  const nextDisabledAt = parsed.disabled === undefined ? target.disabled_at : parsed.disabled ? new Date().toISOString() : null;
  const updatedAt = new Date().toISOString();
  const statements = [c.env.SODAPUSH_DB.prepare("UPDATE users SET username=?1,role=?2,disabled_at=?3,updated_at=?4 WHERE id=?5").bind(nextUsername, nextRole, nextDisabledAt, updatedAt, target.id)];
  if (typeof parsed.password === "string") {
    if (!isOwnerActor) {
      const passwordRecord = await c.env.SODAPUSH_DB.prepare("SELECT password_hash,password_salt FROM users WHERE id=?1 LIMIT 1").bind(target.id).first<{ password_hash: string; password_salt: string }>();
      if (!validString(parsed.currentPassword, 1024) || !passwordRecord || !await verifyPassword(parsed.currentPassword, passwordRecord.password_hash, passwordRecord.password_salt)) return errorResponse(c, 400, "invalid_current_password", "Current password is incorrect");
    }
    const password = await hashPassword(parsed.password);
    statements.push(c.env.SODAPUSH_DB.prepare("UPDATE users SET password_hash=?1,password_salt=?2 WHERE id=?3").bind(password.hash, password.salt, target.id));
    const currentToken = c.req.header("Authorization")?.slice(7).trim();
    if (target.id === user.id && currentToken) {
      statements.push(c.env.SODAPUSH_DB.prepare("UPDATE sessions SET revoked_at=?1 WHERE user_id=?2 AND token_hash<>?3 AND revoked_at IS NULL").bind(Math.floor(Date.now() / 1000), target.id, await sha256Base64Url(currentToken)));
    } else {
      statements.push(c.env.SODAPUSH_DB.prepare("UPDATE sessions SET revoked_at=?1 WHERE user_id=?2 AND revoked_at IS NULL").bind(Math.floor(Date.now() / 1000), target.id));
    }
  }
  await c.env.SODAPUSH_DB.batch(statements);
  return c.json({ user: userDTO({ ...target, username: nextUsername, role: nextRole, disabled_at: nextDisabledAt, updated_at: updatedAt }) });
});

app.get("/v1/apps/:appID/member-candidates", async (c) => {
  const user = await requireUser(c);
  if (user instanceof Response) return user;
  const appID = c.req.param("appID");
  if (!hasRole(await appRole(c.env, user, appID), ["owner", "admin"])) return errorResponse(c, 403, "forbidden", "Member management permission is required");
  const rows = await c.env.SODAPUSH_DB.prepare(`SELECT users.id,users.username,users.role,users.disabled_at,users.created_at,users.updated_at
    FROM users LEFT JOIN app_memberships ON app_memberships.user_id=users.id AND app_memberships.app_id=?1
    WHERE users.role<>'owner' AND users.disabled_at IS NULL AND app_memberships.user_id IS NULL
    ORDER BY users.username COLLATE NOCASE ASC`).bind(appID).all<UserRow>();
  return c.json({ users: rows.results.map(userDTO) });
});

app.get("/v1/apps/:appID/members", async (c) => {
  const user = await requireUser(c);
  if (user instanceof Response) return user;
  const appID = c.req.param("appID");
  if (!hasRole(await appRole(c.env, user, appID), ["owner", "admin", "developer", "viewer"])) return errorResponse(c, 403, "forbidden", "App access is required");
  const rows = await c.env.SODAPUSH_DB.prepare("SELECT users.id,users.username,app_memberships.role,users.disabled_at,app_memberships.created_at FROM app_memberships JOIN users ON users.id=app_memberships.user_id WHERE app_memberships.app_id=?1 ORDER BY app_memberships.created_at ASC").bind(appID).all<{ id: string; username: string; role: AppRole; disabled_at: string | null; created_at: string }>();
  return c.json({ members: rows.results.map((row) => ({ id: row.id, userID: row.id, username: row.username, role: row.role, disabledAt: row.disabled_at, createdAt: row.created_at })) });
});

app.post("/v1/apps/:appID/members/:userID", async (c) => {
  const actor = await requireUser(c);
  if (actor instanceof Response) return actor;
  const appID = c.req.param("appID"), userID = c.req.param("userID");
  if (!hasRole(await appRole(c.env, actor, appID), ["owner", "admin"])) return errorResponse(c, 403, "forbidden", "Member management permission is required");
  const parsed = await jsonBody(c, 16 * 1024);
  if (parsed instanceof Response) return parsed;
  const roles: AppRole[] = ["admin", "developer", "viewer"];
  if (!isRecord(parsed) || !hasOnlyKeys(parsed, ["role"]) || typeof parsed.role !== "string" || !roles.includes(parsed.role as AppRole)) return errorResponse(c, 400, "invalid_member", "Member role must be admin, developer, or viewer");
  const target = await c.env.SODAPUSH_DB.prepare("SELECT id,username,disabled_at FROM users WHERE id=?1 LIMIT 1").bind(userID).first<{ id: string; username: string; disabled_at: string | null }>();
  if (!target) return errorResponse(c, 404, "user_not_found", "User was not found");
  if (target.disabled_at !== null) return errorResponse(c, 409, "user_disabled", "A disabled user cannot be added to an app");
  const existing = await c.env.SODAPUSH_DB.prepare("SELECT role,created_at FROM app_memberships WHERE app_id=?1 AND user_id=?2 LIMIT 1").bind(appID, userID).first<{ role: AppRole; created_at: string }>();
  if (existing?.role === "owner") return errorResponse(c, 409, "owner_membership", "The app owner membership cannot be changed");
  const createdAt = existing?.created_at ?? new Date().toISOString();
  await c.env.SODAPUSH_DB.prepare("INSERT INTO app_memberships (app_id,user_id,role,created_at) VALUES (?1,?2,?3,?4) ON CONFLICT(app_id,user_id) DO UPDATE SET role=excluded.role").bind(appID, userID, parsed.role, createdAt).run();
  return c.json({ member: { id: target.id, userID: target.id, username: target.username, role: parsed.role, disabledAt: null, createdAt } });
});

app.post("/v1/apps/:appID/members/:userID/remove", async (c) => {
  const actor = await requireUser(c);
  if (actor instanceof Response) return actor;
  const appID = c.req.param("appID"), userID = c.req.param("userID");
  if (!hasRole(await appRole(c.env, actor, appID), ["owner", "admin"])) return errorResponse(c, 403, "forbidden", "Member management permission is required");
  const existing = await c.env.SODAPUSH_DB.prepare("SELECT role FROM app_memberships WHERE app_id=?1 AND user_id=?2 LIMIT 1").bind(appID, userID).first<{ role: AppRole }>();
  if (!existing) return errorResponse(c, 404, "member_not_found", "App member was not found");
  if (existing.role === "owner") return errorResponse(c, 409, "owner_membership", "The app owner membership cannot be removed");
  await c.env.SODAPUSH_DB.prepare("DELETE FROM app_memberships WHERE app_id=?1 AND user_id=?2").bind(appID, userID).run();
  return c.body(null, 204);
});

function signedError(status: number, code: string, message: string): Response {
  const requestId = randomRequestID();
  return Response.json({ code, message, requestId }, { status, headers: { "X-Request-ID": requestId } });
}

async function verifySignedRequest(request: Request, env: Env, appID: string, canonicalTarget: string, rawBody: string): Promise<Response | null> {
  const keyID = request.headers.get("X-Soda-Key-ID"), timestamp = request.headers.get("X-Soda-Timestamp"), nonce = request.headers.get("X-Soda-Nonce"), signature = request.headers.get("X-Soda-Signature");
  if (!keyID || !timestamp || !nonce || !signature) return signedError(401, "missing_signature", "Signature headers are required");
  const timestampValue = Number(timestamp), now = Math.floor(Date.now() / 1000);
  if (!Number.isSafeInteger(timestampValue) || Math.abs(now - timestampValue) > 300 || nonce.length < 20 || nonce.length > 128) return signedError(401, "invalid_timestamp", "Request timestamp or nonce is invalid");
  const key = await env.SODAPUSH_DB.prepare("SELECT secret_ciphertext,secret_nonce FROM registration_keys WHERE app_id=?1 AND key_id=?2 AND active=1 LIMIT 1").bind(appID, keyID).first<{ secret_ciphertext: string; secret_nonce: string }>();
  if (!key) return signedError(401, "invalid_key", "Registration key is invalid");
  const secret = await decryptSecret(env.MASTER_KEY, key.secret_ciphertext, key.secret_nonce);
  const expected = await hmacSha256Base64Url(secret, [request.method, canonicalTarget, timestamp, nonce, await sha256Base64Url(rawBody)].join("\n"));
  if (!constantTimeEqual(expected, signature)) return signedError(401, "invalid_signature", "Request signature is invalid");
  try {
    await env.SODAPUSH_DB.prepare("DELETE FROM replay_nonces WHERE expires_at < ?1").bind(now).run();
    await env.SODAPUSH_DB.prepare("INSERT INTO replay_nonces (nonce,key_id,expires_at) VALUES (?1,?2,?3)").bind(nonce, keyID, now + 600).run();
  } catch { return signedError(401, "replayed_request", "Request nonce was already used"); }
  return null;
}

const installationPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

app.post("/v1/apps/:appID/devices/:installationID/register", async (c) => {
  const rawBody = await c.req.text();
  if (new TextEncoder().encode(rawBody).byteLength > 64 * 1024) return errorResponse(c, 413, "request_too_large", "Request body is too large");
  const appID = c.req.param("appID"), installationID = c.req.param("installationID");
  if (!installationPattern.test(installationID)) return errorResponse(c, 400, "invalid_installation_id", "installationID must be a UUID");
  const signatureError = await verifySignedRequest(c.req.raw, c.env, appID, `/v1/apps/${appID}/devices/${installationID}/register`, rawBody);
  if (signatureError) return signatureError;
  let body: DeviceRegistrationRequest;
  try { body = JSON.parse(rawBody) as DeviceRegistrationRequest; } catch { return errorResponse(c, 400, "invalid_json", "Request body must be JSON"); }
  if (!isRecord(body) || typeof body.deviceToken !== "string" || !/^(?:[0-9a-f]{2}){1,256}$/i.test(body.deviceToken)) return errorResponse(c, 400, "invalid_device_token", "deviceToken must be even-length hexadecimal");
  if (body.environment !== "development" && body.environment !== "production") return errorResponse(c, 400, "invalid_environment", "environment must be development or production");
  if (!isRecord(body.context) || !validString(body.context.platform, 32)) return errorResponse(c, 400, "invalid_context", "context.platform is required");
  for (const value of [body.context.appVersion, body.context.appBuild, body.context.locale, body.context.language, body.context.timeZone, body.context.userID]) if (value !== undefined && value !== null && !validString(value, 128)) return errorResponse(c, 400, "invalid_context", "Context values must be strings of at most 128 characters");
  const tags = body.context.tags === undefined || (Array.isArray(body.context.tags) && body.context.tags.length === 0) ? [] : normalizedStringList(body.context.tags);
  if (tags === null) return errorResponse(c, 400, "invalid_tags", "tags must contain between 1 and 50 non-empty strings");
  const now = new Date().toISOString(), token = body.deviceToken.toLowerCase(), tokenHash = await sha256Base64Url(token), encryptedToken = await encryptSecret(c.env.MASTER_KEY, token);
  await c.env.SODAPUSH_DB.batch([
    c.env.SODAPUSH_DB.prepare("DELETE FROM devices WHERE app_id=?1 AND environment=?2 AND device_token_hash=?3 AND installation_id<>?4").bind(appID, body.environment, tokenHash, installationID),
    c.env.SODAPUSH_DB.prepare(`INSERT INTO devices (app_id,installation_id,environment,device_token_ciphertext,device_token_nonce,device_token_hash,platform,app_version,app_build,locale,language,time_zone,user_id,tags_json,status,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,'active',?15,?15) ON CONFLICT(app_id,installation_id,environment) DO UPDATE SET device_token_ciphertext=excluded.device_token_ciphertext,device_token_nonce=excluded.device_token_nonce,device_token_hash=excluded.device_token_hash,platform=excluded.platform,app_version=excluded.app_version,app_build=excluded.app_build,locale=excluded.locale,language=excluded.language,time_zone=excluded.time_zone,user_id=excluded.user_id,tags_json=excluded.tags_json,status='active',updated_at=excluded.updated_at`).bind(appID, installationID, body.environment, encryptedToken.ciphertext, encryptedToken.nonce, tokenHash, body.context.platform, body.context.appVersion ?? null, body.context.appBuild ?? null, body.context.locale ?? null, body.context.language ?? null, body.context.timeZone ?? null, body.context.userID ?? null, JSON.stringify(tags), now),
  ]);
  return c.json({ installationID, environment: body.environment, language: body.context.language ?? null, userID: body.context.userID ?? null, tags, updatedAt: now });
});

app.post("/v1/apps/:appID/devices/:installationID/unregister", async (c) => {
  const appID = c.req.param("appID"), installationID = c.req.param("installationID");
  if (!installationPattern.test(installationID)) return errorResponse(c, 400, "invalid_installation_id", "installationID must be a UUID");
  const rawBody = await c.req.text();
  if (new TextEncoder().encode(rawBody).byteLength > 4096) return errorResponse(c, 413, "request_too_large", "Request body is too large");
  const canonicalTarget = `/v1/apps/${appID}/devices/${installationID}/unregister`;
  const signatureError = await verifySignedRequest(c.req.raw, c.env, appID, canonicalTarget, rawBody);
  if (signatureError) return signatureError;
  let body: unknown;
  try { body = JSON.parse(rawBody); } catch { return errorResponse(c, 400, "invalid_json", "Request body must be JSON"); }
  if (!isRecord(body) || !hasOnlyKeys(body, ["environment"]) || !validEnvironment(body.environment)) return errorResponse(c, 400, "invalid_environment", "environment must be development or production");
  const environment = body.environment;
  await c.env.SODAPUSH_DB.prepare("UPDATE devices SET status='inactive',updated_at=?1 WHERE app_id=?2 AND installation_id=?3 AND environment=?4").bind(new Date().toISOString(), appID, installationID, environment).run();
  return c.body(null, 204);
});

export async function processPushJob(env: Env, jobID: string): Promise<void> {
  const job = await env.SODAPUSH_DB.prepare("SELECT id,app_id,environment,request_json,status FROM push_jobs WHERE id=?1 LIMIT 1").bind(jobID).first<{ id: string; app_id: string; environment: "development" | "production"; request_json: string; status: string }>();
  if (!job || job.status !== "queued") return;
  await env.SODAPUSH_DB.prepare("UPDATE push_jobs SET status='running',updated_at=?1 WHERE id=?2 AND status='queued'").bind(new Date().toISOString(), jobID).run();
  try {
    const appRecord = await env.SODAPUSH_DB.prepare("SELECT bundle_id FROM apps WHERE id=?1 AND disabled_at IS NULL LIMIT 1").bind(job.app_id).first<{ bundle_id: string }>();
    const request = JSON.parse(job.request_json) as { credentialID?: string | null; pushType: "alert" | "background" | "liveactivity"; target: { all?: boolean; installationIds?: string[]; tags?: string[]; languages?: string[]; userIDs?: string[] }; payload: Record<string, unknown> };
    const stored = request.credentialID
      ? await env.SODAPUSH_DB.prepare("SELECT team_id,key_id,p8_ciphertext,p8_nonce FROM apns_credentials WHERE app_id=?1 AND id=?2 AND environment=?3 LIMIT 1").bind(job.app_id, request.credentialID, job.environment).first<{ team_id: string; key_id: string; p8_ciphertext: string; p8_nonce: string }>()
      : await env.SODAPUSH_DB.prepare("SELECT team_id,key_id,p8_ciphertext,p8_nonce FROM apns_credentials WHERE app_id=?1 AND environment=?2 ORDER BY is_default DESC,updated_at DESC LIMIT 1").bind(job.app_id, job.environment).first<{ team_id: string; key_id: string; p8_ciphertext: string; p8_nonce: string }>();
    if (!appRecord || !stored) { await env.SODAPUSH_DB.prepare("UPDATE push_jobs SET status='failed',failure_count=failure_count+1,updated_at=?1 WHERE id=?2").bind(new Date().toISOString(), jobID).run(); return; }
    const devices = await env.SODAPUSH_DB.prepare("SELECT installation_id,device_token_ciphertext,device_token_nonce,language,user_id,tags_json FROM devices WHERE app_id=?1 AND environment=?2 AND status='active'").bind(job.app_id, job.environment).all<{ installation_id: string; device_token_ciphertext: string; device_token_nonce: string; language: string | null; user_id: string | null; tags_json: string }>();
    const selected = devices.results.filter((device) => {
      if (request.target.all === true) return true;
      if (request.target.installationIds) return request.target.installationIds.includes(device.installation_id);
      if (request.target.languages) return device.language !== null && request.target.languages.includes(device.language);
      if (request.target.userIDs) return device.user_id !== null && request.target.userIDs.includes(device.user_id);
      if (request.target.tags) {
        try {
          const deviceTags = JSON.parse(device.tags_json) as unknown;
          return Array.isArray(deviceTags) && request.target.tags.some((tag) => deviceTags.includes(tag));
        } catch { return false; }
      }
      return false;
    });
    await env.SODAPUSH_DB.prepare("UPDATE push_jobs SET total_count=?1,updated_at=?2 WHERE id=?3").bind(selected.length, new Date().toISOString(), jobID).run();
    let success = 0, failure = 0;
    for (const device of selected) {
      const previous = await env.SODAPUSH_DB.prepare("SELECT id,status FROM deliveries WHERE job_id=?1 AND device_id=?2").bind(jobID, device.installation_id).first<{ id: string; status: string }>();
      if (previous?.status === "sent") { success += 1; continue; }
      const deliveryID = previous?.id ?? crypto.randomUUID(), createdAt = new Date().toISOString();
      if (!previous) await env.SODAPUSH_DB.prepare("INSERT OR IGNORE INTO deliveries (id,job_id,device_id,status,created_at,updated_at) VALUES (?1,?2,?3,'queued',?4,?4)").bind(deliveryID, jobID, device.installation_id, createdAt).run();
      const token = await decryptSecret(env.MASTER_KEY, device.device_token_ciphertext, device.device_token_nonce);
      const response = await sendToAPNs(env, { teamID: stored.team_id, keyID: stored.key_id, p8Ciphertext: stored.p8_ciphertext, p8Nonce: stored.p8_nonce }, job.environment, appRecord.bundle_id, token, JSON.stringify(request.payload), request.pushType);
      if (response.status === 200) { success += 1; await env.SODAPUSH_DB.prepare("UPDATE deliveries SET status='sent',apns_id=?1,apns_status=?2,reason=NULL,updated_at=?3 WHERE id=?4").bind(response.apnsID, response.status, new Date().toISOString(), deliveryID).run(); }
      else {
        failure += 1;
        const invalid = ["BadDeviceToken", "DeviceTokenNotForTopic", "Unregistered"].includes(response.reason ?? "");
        await env.SODAPUSH_DB.prepare("UPDATE deliveries SET status=?1,apns_id=?2,apns_status=?3,reason=?4,updated_at=?5 WHERE id=?6").bind(invalid ? "invalid" : "failed", response.apnsID, response.status, response.reason, new Date().toISOString(), deliveryID).run();
        if (invalid) await env.SODAPUSH_DB.prepare("UPDATE devices SET status='inactive',updated_at=?1 WHERE app_id=?2 AND installation_id=?3 AND environment=?4").bind(new Date().toISOString(), job.app_id, device.installation_id, job.environment).run();
      }
    }
    await env.SODAPUSH_DB.prepare("UPDATE push_jobs SET status=?1,success_count=?2,failure_count=?3,updated_at=?4 WHERE id=?5").bind(failure === 0 ? "completed" : success === 0 ? "failed" : "partial", success, failure, new Date().toISOString(), jobID).run();
  } catch (error) {
    await env.SODAPUSH_DB.prepare("UPDATE push_jobs SET status='queued',updated_at=?1 WHERE id=?2").bind(new Date().toISOString(), jobID).run();
    throw error;
  }
}

export async function queue(batch: MessageBatch<PushMessage>, env: Env): Promise<void> {
  for (const message of batch.messages) {
    try { await processPushJob(env, message.body.jobID); message.ack(); }
    catch (error) { console.error("push job failed", message.body.jobID, error); message.retry(); }
  }
}

app.notFound((c) => errorResponse(c, 404, "not_found", "API endpoint not found"));
app.onError((error, c) => { console.error("request failed", error); return errorResponse(c, 500, "internal_error", "An internal error occurred"); });

export default {
  fetch(request: Request, env: Env, executionContext: ExecutionContext) { return app.fetch(request, env, executionContext); },
  queue,
} satisfies ExportedHandler<Env, PushMessage>;
