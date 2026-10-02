import { afterEach, describe, expect, it, vi } from "vitest";
import { sendToAPNs } from "../src/apns";
import { encryptSecret } from "../src/crypto";
import type { Env } from "../src/types";

afterEach(() => vi.unstubAllGlobals());

describe("APNs notification identity", () => {
  it("passes a recallable identifier as apns-collapse-id without changing the payload", async () => {
    const masterKey = Buffer.alloc(32, 4).toString("base64url");
    const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    const privateKey = await crypto.subtle.exportKey("pkcs8", pair.privateKey);
    const pem = `-----BEGIN PRIVATE KEY-----\n${Buffer.from(privateKey).toString("base64")}\n-----END PRIVATE KEY-----`;
    const encrypted = await encryptSecret(masterKey, pem);
    const payload = JSON.stringify({ aps: { alert: "Hello" } });
    let headers: Headers | undefined;
    let body: BodyInit | null | undefined;
    vi.stubGlobal("fetch", vi.fn(async (_url: string, init: RequestInit) => {
      headers = new Headers(init.headers);
      body = init.body;
      return new Response(null, { status: 200, headers: { "apns-id": "apns-test-id" } });
    }));

    const result = await sendToAPNs(
      { MASTER_KEY: masterKey } as Env,
      { teamID: "TEAM", keyID: "KEY", p8Ciphertext: encrypted.ciphertext, p8Nonce: encrypted.nonce },
      "production", "com.example.app", "device-token", payload, "alert", "push-job-id"
    );

    expect(result).toMatchObject({ status: 200, apnsID: "apns-test-id" });
    expect(headers?.get("apns-collapse-id")).toBe("push-job-id");
    expect(headers?.get("apns-push-type")).toBe("alert");
    expect(body).toBe(payload);
  });
});
