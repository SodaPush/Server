import { createClient, type Client } from "@libsql/client";
import { beforeEach, describe, expect, it } from "vitest";
import { app } from "../src/index";
import { hmacSha256Base64Url, sha256Base64Url } from "../src/crypto";
import type { Env } from "../src/types";
import { readFile } from "node:fs/promises";

class TestStatement {
  private args: unknown[] = [];

  constructor(readonly client: Client, readonly sql: string) {}

  bind(...args: unknown[]): TestStatement {
    this.args = args;
    return this;
  }

  async first<T>(): Promise<T | null> {
    const result = await this.client.execute({ sql: this.sql, args: this.args as never[] });
    return (result.rows[0] as T | undefined) ?? null;
  }

  async all<T>(): Promise<{ results: T[] }> {
    const result = await this.client.execute({ sql: this.sql, args: this.args as never[] });
    return { results: result.rows as T[] };
  }

  async run(): Promise<unknown> {
    return this.client.execute({ sql: this.sql, args: this.args as never[] });
  }

  get boundArgs(): unknown[] { return this.args; }
}

class TestDatabase {
  constructor(private readonly client: Client) {}

  prepare(sql: string): TestStatement { return new TestStatement(this.client, sql); }

  async batch(statements: TestStatement[]): Promise<unknown> {
    return this.client.batch(statements.map(({ sql, boundArgs }) => ({ sql, args: boundArgs as never[] })) as never[]);
  }
}

describe("API contract", () => {
  let client: Client;
  let env: Env;

  beforeEach(async () => {
    client = createClient({ url: ":memory:" });
    const initial = await readFile(new URL("../migrations/0001_initial.sql", import.meta.url), "utf8");
    const accounts = await readFile(new URL("../migrations/0002_accounts_pushes.sql", import.meta.url), "utf8");
    await client.executeMultiple(`${initial}\n${accounts}`);
    env = {
      SODAPUSH_DB: new TestDatabase(client) as unknown as D1Database,
      MASTER_KEY: Buffer.alloc(32, 7).toString("base64url"),
      BOOTSTRAP_TOKEN: "bootstrap-test-token",
      APP_VERSION: "test",
    };
  });

  it("bootstraps, creates an app, and returns camelCase management DTOs", async () => {
    const bootstrap = await request("/v1/bootstrap", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Soda-Bootstrap-Token": "bootstrap-test-token" },
      body: JSON.stringify({ username: "owner", password: "a-secure-test-password" }),
    });
    expect(bootstrap.status).toBe(201);
    const { accessToken } = await bootstrap.json() as { accessToken: string };

    const created = await request("/v1/apps", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${accessToken}` },
      body: JSON.stringify({ name: "Example", bundleID: "com.example.app" }),
    });
    expect(created.status).toBe(201);

    const listed = await request("/v1/apps", { headers: { Authorization: `Bearer ${accessToken}` } });
    expect(listed.status).toBe(200);
    const body = await listed.json() as { apps: Array<Record<string, unknown>> };
    expect(body.apps[0]).toMatchObject({ name: "Example", bundleID: "com.example.app" });
    expect(body.apps[0]).toHaveProperty("createdAt");
    expect(body.apps[0]).not.toHaveProperty("bundle_id");
  });

  it("registers and unregisters only the signed environment", async () => {
    const { appID, keyID, secret } = await createApplication();
    const installationID = "d1b28f5a-f77b-44d5-a00a-68b6529e553a";
    const path = `/v1/apps/${appID}/devices/${installationID}`;
    const registrationBody = JSON.stringify({
      deviceToken: "00abff",
      environment: "production",
      context: { platform: "iOS" },
    });
    const registration = await signedRequest(path, "PUT", registrationBody, keyID, secret);
    expect(registration.status).toBe(200);

    const canonicalTarget = `${path}?environment=production`;
    const removal = await signedRequest(canonicalTarget, "DELETE", "", keyID, secret);
    expect(removal.status).toBe(204);
    const row = await client.execute({
      sql: "SELECT status FROM devices WHERE app_id = ? AND installation_id = ? AND environment = ?",
      args: [appID, installationID, "production"],
    });
    expect(row.rows[0]?.status).toBe("inactive");
  });

  async function createApplication(): Promise<{ appID: string; keyID: string; secret: string }> {
    const bootstrap = await request("/v1/bootstrap", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Soda-Bootstrap-Token": "bootstrap-test-token" },
      body: JSON.stringify({ username: "owner", password: "a-secure-test-password" }),
    });
    const { accessToken } = await bootstrap.json() as { accessToken: string };
    const created = await request("/v1/apps", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${accessToken}` },
      body: JSON.stringify({ name: "Example", bundleID: "com.example.app" }),
    });
    const body = await created.json() as {
      app: { id: string };
      registrationKey: { keyID: string; secret: string };
    };
    return { appID: body.app.id, ...body.registrationKey };
  }

  async function signedRequest(canonicalTarget: string, method: string, body: string, keyID: string, secret: string): Promise<Response> {
    const timestamp = String(Math.floor(Date.now() / 1000));
    const nonce = crypto.randomUUID().replaceAll("-", "");
    const bodyHash = await sha256Base64Url(body);
    const signature = await hmacSha256Base64Url(secret, [method, canonicalTarget, timestamp, nonce, bodyHash].join("\n"));
    return request(canonicalTarget, {
      method,
      headers: {
        "Content-Type": "application/json",
        "X-Soda-Key-ID": keyID,
        "X-Soda-Timestamp": timestamp,
        "X-Soda-Nonce": nonce,
        "X-Soda-Signature": signature,
      },
      body: body || undefined,
    });
  }

  function request(path: string, init?: RequestInit): Promise<Response> {
    return Promise.resolve(app.fetch(new Request(`https://push.example.com${path}`, init), env));
  }
});
