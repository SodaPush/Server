const encoder = new TextEncoder();

function base64UrlEncode(data: ArrayBuffer | Uint8Array): string {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function base64UrlDecode(value: string): ArrayBuffer {
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0)).buffer;
}

async function importAesKey(masterKey: string): Promise<CryptoKey> {
  const raw = base64UrlDecode(masterKey);
  if (raw.byteLength !== 32) throw new Error("MASTER_KEY must be a 32-byte base64url value");
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}

export async function encryptSecret(masterKey: string, plaintext: string): Promise<{ ciphertext: string; nonce: string }> {
  const key = await importAesKey(masterKey);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, encoder.encode(plaintext));
  return { ciphertext: base64UrlEncode(ciphertext), nonce: base64UrlEncode(nonce) };
}

export async function decryptSecret(masterKey: string, ciphertext: string, nonce: string): Promise<string> {
  const key = await importAesKey(masterKey);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64UrlDecode(nonce) },
    key,
    base64UrlDecode(ciphertext)
  );
  return new TextDecoder().decode(plaintext);
}

export async function sha256Base64Url(value: string | ArrayBuffer): Promise<string> {
  const data = typeof value === "string" ? encoder.encode(value) : value;
  return base64UrlEncode(await crypto.subtle.digest("SHA-256", data));
}

export async function hmacSha256Base64Url(secret: string, value: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return base64UrlEncode(await crypto.subtle.sign("HMAC", key, encoder.encode(value)));
}

export function constantTimeEqual(left: string, right: string): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return difference === 0;
}

export function randomRequestID(): string {
  return crypto.randomUUID();
}

export function base64UrlEncodeBytes(data: Uint8Array): string {
  return base64UrlEncode(data);
}
