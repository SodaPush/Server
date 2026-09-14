import { describe, expect, it } from "vitest";
import { constantTimeEqual, decryptSecret, encryptSecret, hmacSha256Base64Url, sha256Base64Url } from "../src/crypto";
import { hashPassword, verifyPassword } from "../src/auth";

const key = () => Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("base64url");

describe("security primitives", () => {
  it("round-trips authenticated encryption and rejects a wrong key", async () => {
    const encrypted = await encryptSecret(key(), "sensitive");
    expect(encrypted.ciphertext).not.toContain("sensitive");
    const master = key();
    const value = await encryptSecret(master, "secret");
    expect(await decryptSecret(master, value.ciphertext, value.nonce)).toBe("secret");
    await expect(decryptSecret(key(), value.ciphertext, value.nonce)).rejects.toThrow();
  });
  it("verifies passwords", async () => {
    const stored = await hashPassword("correct horse battery staple");
    expect(await verifyPassword("correct horse battery staple", stored.hash, stored.salt)).toBe(true);
    expect(await verifyPassword("wrong", stored.hash, stored.salt)).toBe(false);
  });
  it("keeps signing primitives deterministic", async () => {
    expect(await sha256Base64Url("hello")).toBe("LPJNul-wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ");
    expect((await hmacSha256Base64Url("secret", "payload")).length).toBe(43);
    expect(constantTimeEqual("same", "same")).toBe(true);
    expect(constantTimeEqual("same", "diff")).toBe(false);
  });
});
