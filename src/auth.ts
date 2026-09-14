import { sha256Base64Url } from "./crypto";
import { constantTimeEqual } from "./crypto";
import type { Env, SessionUser } from "./types";

const encoder = new TextEncoder();

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function randomToken(bytes = 32): string {
  return base64Url(crypto.getRandomValues(new Uint8Array(bytes)));
}

async function derivePassword(password: string, salt: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    // Cloudflare Workers rejects PBKDF2 iteration counts above 100,000.
    { name: "PBKDF2", salt: encoder.encode(salt), iterations: 100_000, hash: "SHA-256" },
    key,
    256
  );
  return base64Url(new Uint8Array(bits));
}

export async function hashPassword(password: string, salt = randomToken(16)): Promise<{ hash: string; salt: string }> {
  return { hash: await derivePassword(password, salt), salt };
}

export async function verifyPassword(password: string, expectedHash: string, salt: string): Promise<boolean> {
  const actual = await derivePassword(password, salt);
  return constantTimeEqual(actual, expectedHash);
}

export async function createSession(env: Env, userID: string): Promise<string> {
  const token = randomToken();
  const tokenHash = await sha256Base64Url(token);
  const now = new Date();
  await env.SODAPUSH_DB.prepare(
    "INSERT INTO sessions (id, user_id, token_hash, expires_at, created_at) VALUES (?1, ?2, ?3, ?4, ?5)"
  ).bind(crypto.randomUUID(), userID, tokenHash, Math.floor(now.getTime() / 1000) + 60 * 60 * 24 * 30, now.toISOString()).run();
  return token;
}

export async function getSessionUser(request: Request, env: Env): Promise<SessionUser | null> {
  const authorization = request.headers.get("Authorization");
  if (!authorization?.startsWith("Bearer ")) return null;
  const tokenHash = await sha256Base64Url(authorization.slice(7).trim());
  return env.SODAPUSH_DB.prepare(
    `SELECT users.id, users.username, users.role
     FROM sessions JOIN users ON users.id = sessions.user_id
     WHERE sessions.token_hash = ?1 AND sessions.revoked_at IS NULL
       AND sessions.expires_at > ?2 AND users.disabled_at IS NULL LIMIT 1`
  ).bind(tokenHash, Math.floor(Date.now() / 1000)).first<SessionUser>();
}

export { randomToken };
