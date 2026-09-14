import { decryptSecret } from "./crypto";
import type { Env } from "./types";

function decodeBase64URL(value: string): ArrayBuffer {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - value.length % 4) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0)).buffer;
}

function encodeBase64URL(value: Uint8Array | ArrayBuffer): string {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

async function createProviderToken(teamID: string, keyID: string, p8: string): Promise<string> {
  const keyData = decodeBase64URL(p8.replace(/-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\s/g, ""));
  const privateKey = await crypto.subtle.importKey(
    "pkcs8",
    keyData,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"]
  );
  const header = encodeBase64URL(new TextEncoder().encode(JSON.stringify({ alg: "ES256", kid: keyID })));
  const payload = encodeBase64URL(new TextEncoder().encode(JSON.stringify({ iss: teamID, iat: Math.floor(Date.now() / 1000) })));
  const signingInput = `${header}.${payload}`;
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privateKey,
    new TextEncoder().encode(signingInput)
  );
  return `${signingInput}.${encodeBase64URL(signature)}`;
}

const providerTokenCache = new Map<string, { token: string; createdAt: number }>();

async function providerToken(teamID: string, keyID: string, p8: string): Promise<string> {
  const cacheKey = `${teamID}:${keyID}`;
  const cached = providerTokenCache.get(cacheKey);
  const now = Math.floor(Date.now() / 1000);
  if (cached && now - cached.createdAt < 50 * 60) return cached.token;
  const token = await createProviderToken(teamID, keyID, p8);
  providerTokenCache.set(cacheKey, { token, createdAt: now });
  return token;
}

export interface APNsCredential {
  teamID: string;
  keyID: string;
  p8Ciphertext: string;
  p8Nonce: string;
}

export async function sendToAPNs(
  env: Env,
  credential: APNsCredential,
  environment: "development" | "production",
  bundleID: string,
  deviceToken: string,
  payload: string,
  pushType: "alert" | "background" | "liveactivity" = "alert"
): Promise<{ status: number; apnsID: string | null; reason: string | null }> {
  const p8 = await decryptSecret(env.MASTER_KEY, credential.p8Ciphertext, credential.p8Nonce);
  const token = await providerToken(credential.teamID, credential.keyID, p8);
  const host = environment === "development" ? "api.sandbox.push.apple.com" : "api.push.apple.com";
  const topic = pushType === "liveactivity" ? `${bundleID}.push-type.liveactivity` : bundleID;
  const response = await fetch(`https://${host}/3/device/${deviceToken}`, {
    method: "POST",
    headers: {
      authorization: `bearer ${token}`,
      "apns-topic": topic,
      "apns-push-type": pushType,
      "apns-priority": pushType === "background" ? "5" : "10",
      "content-type": "application/json",
    },
    body: payload,
  });
  let reason: string | null = null;
  if (!response.ok) {
    const body = await response.json().catch(() => null) as { reason?: string } | null;
    reason = body?.reason ?? null;
  }
  return { status: response.status, apnsID: response.headers.get("apns-id"), reason };
}
