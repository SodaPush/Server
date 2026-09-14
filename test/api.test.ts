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
    const { appID, keyID, secret, accessToken } = await createApplication();
    const installationID = "d1b28f5a-f77b-44d5-a00a-68b6529e553a";
    const path = `/v1/apps/${appID}/devices/${installationID}`;
    const registrationBody = JSON.stringify({
      deviceToken: "00abff",
      environment: "production",
      context: { platform: "iOS" },
    });
    const registration = await signedRequest(path, "PUT", registrationBody, keyID, secret);
    expect(registration.status).toBe(200);

    const devices = await request(`/v1/apps/${appID}/devices`, { headers: { Authorization: `Bearer ${accessToken}` } });
    const device = (await devices.json() as { devices: Array<Record<string, unknown>> }).devices[0];
    expect(device).toMatchObject({ id: `${installationID}:production`, installationID, appVersion: null, status: "active" });

    const canonicalTarget = `${path}?environment=production`;
    const removal = await signedRequest(canonicalTarget, "DELETE", "", keyID, secret);
    expect(removal.status).toBe(204);
    const row = await client.execute({
      sql: "SELECT status FROM devices WHERE app_id = ? AND installation_id = ? AND environment = ?",
      args: [appID, installationID, "production"],
    });
    expect(row.rows[0]?.status).toBe("inactive");
  });

  it("supports the practical management lifecycle without exposing stored secrets", async () => {
    const { appID, accessToken } = await createApplication();
    const authorization = { Authorization: `Bearer ${accessToken}` };

    const apps = await request("/v1/apps", { headers: authorization });
    expect((await apps.json() as { apps: Array<{ role: string }> }).apps[0]?.role).toBe("owner");

    const updated = await request(`/v1/apps/${appID}`, {
      method: "PATCH",
      headers: { ...authorization, "Content-Type": "application/json" },
      body: JSON.stringify({ name: "Renamed" }),
    });
    expect(updated.status).toBe(200);
    expect((await updated.json() as { app: { name: string } }).app.name).toBe("Renamed");

    await client.batch([
      { sql: "INSERT INTO push_jobs(id,app_id,environment,request_json,status,total_count,success_count,failure_count,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)", args: ["job-1", appID, "production", JSON.stringify({ pushType: "alert", target: { all: true }, payload: { aps: { alert: "Hi" } } }), "partial", 2, 1, 1, "now", "now"] },
      { sql: "INSERT INTO deliveries(id,job_id,device_id,status,apns_status,reason,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)", args: ["delivery-1", "job-1", "device-1", "failed", 410, "Unregistered", "now", "now"] },
    ]);
    const pushes = await request(`/v1/apps/${appID}/pushes`, { headers: authorization });
    expect((await pushes.json() as { pushes: Array<{ id: string }> }).pushes[0]?.id).toBe("job-1");
    const push = await request(`/v1/apps/${appID}/pushes/job-1`, { headers: authorization });
    const pushBody = await push.json() as { push: { failureCount: number }; deliveries: Array<{ reason: string }> };
    expect(pushBody.push.failureCount).toBe(1);
    expect(pushBody.deliveries[0]?.reason).toBe("Unregistered");

    const apns = await request(`/v1/apps/${appID}/apns-credentials`, {
      method: "POST",
      headers: { ...authorization, "Content-Type": "application/json" },
      body: JSON.stringify({ teamID: "TEAM123", keyID: "KEY123", p8: "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----" }),
    });
    expect(apns.status).toBe(200);
    expect(await apns.json()).not.toHaveProperty("credential.p8");
    const credentials = await request(`/v1/apps/${appID}/apns-credentials`, { headers: authorization });
    expect(JSON.stringify(await credentials.json())).not.toContain("PRIVATE KEY");

    const registration = await request(`/v1/apps/${appID}/registration-keys`, { method: "POST", headers: authorization });
    expect(registration.status).toBe(201);
    expect((await registration.json() as { registrationKey: { secret: string } }).registrationKey.secret).toBeTruthy();
    const keyList = await request(`/v1/apps/${appID}/registration-keys`, { headers: authorization });
    expect(JSON.stringify(await keyList.json())).not.toContain("secret");

    const createdUser = await request("/v1/users", {
      method: "POST",
      headers: { ...authorization, "Content-Type": "application/json" },
      body: JSON.stringify({ username: "developer", password: "another-secure-password", role: "developer" }),
    });
    expect(createdUser.status).toBe(201);
    const developerID = (await createdUser.json() as { user: { id: string } }).user.id;
    const membership = await request(`/v1/apps/${appID}/members/${developerID}`, {
      method: "PUT",
      headers: { ...authorization, "Content-Type": "application/json" },
      body: JSON.stringify({ role: "developer" }),
    });
    expect(membership.status).toBe(200);
    expect((await membership.json() as { member: { role: string } }).member.role).toBe("developer");

    const developerLogin = await request("/v1/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "developer", password: "another-secure-password" }),
    });
    const developerToken = (await developerLogin.json() as { accessToken: string }).accessToken;
    const forbiddenUpdate = await request(`/v1/apps/${appID}`, {
      method: "PATCH",
      headers: { Authorization: `Bearer ${developerToken}`, "Content-Type": "application/json" },
      body: JSON.stringify({ name: "Not Allowed" }),
    });
    expect(forbiddenUpdate.status).toBe(403);

    const lastOwner = await request(`/v1/users/${(await client.execute("SELECT id FROM users WHERE role='owner'")).rows[0]?.id}`, {
      method: "PATCH",
      headers: { ...authorization, "Content-Type": "application/json" },
      body: JSON.stringify({ disabled: true }),
    });
    expect(lastOwner.status).toBe(409);

    expect((await request("/v1/auth/logout", { method: "POST", headers: authorization })).status).toBe(204);
    expect((await request("/v1/me", { headers: authorization })).status).toBe(401);
  });

  async function createApplication(): Promise<{ appID: string; keyID: string; secret: string; accessToken: string }> {
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
    return { appID: body.app.id, accessToken, ...body.registrationKey };
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
