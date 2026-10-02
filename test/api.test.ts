import { createClient, type Client } from "@libsql/client";
import { beforeEach, describe, expect, it } from "vitest";
import { app, processPushJob } from "../src/index";
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
    const targeting = await readFile(new URL("../migrations/0003_targeting_and_credentials.sql", import.meta.url), "utf8");
    const cancellation = await readFile(new URL("../migrations/0004_local_cancellation.sql", import.meta.url), "utf8");
    const recall = await readFile(new URL("../migrations/0005_push_recall.sql", import.meta.url), "utf8");
    await client.executeMultiple(`${initial}\n${accounts}\n${targeting}\n${cancellation}\n${recall}`);
    env = {
      SODAPUSH_DB: new TestDatabase(client) as unknown as D1Database,
      MASTER_KEY: Buffer.alloc(32, 7).toString("base64url"),
      BOOTSTRAP_TOKEN: "bootstrap-test-token",
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
      context: { platform: "iOS", language: "en", userID: "customer-42", tags: ["beta", "paid"] },
    });
    const registration = await signedRequest(`${path}/register`, "POST", registrationBody, keyID, secret);
    expect(registration.status).toBe(200);

    const devices = await request(`/v1/apps/${appID}/devices`, { headers: { Authorization: `Bearer ${accessToken}` } });
    const device = (await devices.json() as { devices: Array<Record<string, unknown>> }).devices[0];
    expect(device).toMatchObject({ id: `${installationID}:production`, installationID, appVersion: null, language: "en", userID: "customer-42", tags: ["beta", "paid"], status: "active" });

    const removal = await signedRequest(`${path}/unregister`, "POST", JSON.stringify({ environment: "production" }), keyID, secret);
    expect(removal.status).toBe(204);
    const row = await client.execute({
      sql: "SELECT status FROM devices WHERE app_id = ? AND installation_id = ? AND environment = ?",
      args: [appID, installationID, "production"],
    });
    expect(row.rows[0]?.status).toBe("inactive");
  });

  it("cancels a local schedule from its original push record", async () => {
    const { appID, accessToken } = await createApplication();
    const authorization = { Authorization: `Bearer ${accessToken}` };
    const fireAt = new Date(Date.now() + 3_600_000).toISOString();
    const originalRequest = {
      environment: "production",
      pushType: "background",
      target: { tags: ["launch"] },
      payload: { aps: { "content-available": 1 }, sodapush: { version: 1, localNotification: { action: "schedule", identifier: "launch-reminder", fireAt, body: "Launch" } } },
    };
    await client.execute({ sql: "INSERT INTO push_jobs(id,app_id,environment,request_json,status,total_count,success_count,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)", args: ["original-local", appID, "production", JSON.stringify(originalRequest), "completed", 2, 1, "now", "now"] });
    await client.execute({ sql: "INSERT INTO deliveries(id,job_id,device_id,status,created_at,updated_at) VALUES(?,?,?,?,?,?)", args: ["original-delivery", "original-local", "device-1", "sent", "now", "now"] });
    const queued: unknown[] = [];
    env.PUSH_QUEUE = { send: async (body: unknown) => { queued.push(body); } } as unknown as Queue;

    const cancelled = await request(`/v1/apps/${appID}/pushes/original-local/cancel-local`, { method: "POST", headers: authorization });
    expect(cancelled.status).toBe(202);
    const cancellation = await cancelled.json() as { jobID: string; originalJobID: string };
    expect(cancellation.originalJobID).toBe("original-local");
    expect(queued).toEqual([{ jobID: cancellation.jobID }]);
    const original = await request(`/v1/apps/${appID}/pushes/original-local`, { headers: authorization });
    expect((await original.json() as { push: { status: string; localCancellationJobID: string } }).push).toMatchObject({ status: "cancelled", localCancellationJobID: cancellation.jobID });
    const created = await client.execute({ sql: "SELECT request_json FROM push_jobs WHERE id=?", args: [cancellation.jobID] });
    const createdRequest = JSON.parse(String(created.rows[0]?.request_json)) as { cancellationOf: string; target: { tags: string[] }; payload: { sodapush: { localNotification: { action: string; identifier: string } } } };
    expect(createdRequest).toMatchObject({ cancellationOf: "original-local", target: { tags: ["launch"] }, payload: { sodapush: { localNotification: { action: "cancel", identifier: "launch-reminder" } } } });
    expect((await request(`/v1/apps/${appID}/pushes/original-local/cancel-local`, { method: "POST", headers: authorization })).status).toBe(409);
    expect((await request(`/v1/apps/${appID}/pushes/original-local/delete`, { method: "POST", headers: authorization })).status).toBe(409);
    expect(queued).toHaveLength(1);

    await client.execute({ sql: "INSERT INTO push_jobs(id,app_id,environment,request_json,status,total_count,success_count,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)", args: ["another-local", appID, "production", JSON.stringify(originalRequest), "completed", 1, 1, "now", "now"] });
    env.PUSH_QUEUE = undefined;
    const unavailable = await request(`/v1/apps/${appID}/pushes/another-local/cancel-local`, { method: "POST", headers: authorization });
    expect(unavailable.status).toBe(503);
    expect((await client.execute("SELECT local_cancelled_at FROM push_jobs WHERE id='another-local'")).rows[0]?.local_cancelled_at).toBeNull();

    env.PUSH_QUEUE = { send: async () => { throw new Error("Queue unavailable"); } } as unknown as Queue;
    const enqueueFailure = await request(`/v1/apps/${appID}/pushes/another-local/cancel-local`, { method: "POST", headers: authorization });
    expect(enqueueFailure.status).toBe(500);
    expect((await client.execute("SELECT local_cancelled_at FROM push_jobs WHERE id='another-local'")).rows[0]?.local_cancelled_at).toBeNull();
    expect((await client.execute({ sql: "SELECT COUNT(*) AS count FROM push_jobs WHERE app_id=?", args: [appID] })).rows[0]?.count).toBe(3);
  });

  it("generates a local schedule identifier and reuses it for cancellation", async () => {
    const { appID, accessToken } = await createApplication();
    const authorization = { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" };
    const queued: Array<{ jobID: string }> = [];
    env.PUSH_QUEUE = { send: async (body: { jobID: string }) => { queued.push(body); } } as unknown as Queue;
    const fireAt = new Date(Date.now() + 3_600_000).toISOString();
    const command = { action: "schedule", fireAt, title: "Reminder", body: "Time to check in" };
    const requestBody = { environment: "production", pushType: "background", target: { all: true }, payload: { aps: { "content-available": 1 }, sodapush: { version: 1, localNotification: command } } };

    const created = await request(`/v1/apps/${appID}/pushes`, { method: "POST", headers: authorization, body: JSON.stringify(requestBody) });
    expect(created.status).toBe(202);
    const createdBody = await created.json() as { jobID: string; localNotificationIdentifier: string };
    expect(createdBody.localNotificationIdentifier).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
    const originalRow = await client.execute({ sql: "SELECT request_json FROM push_jobs WHERE id=?", args: [createdBody.jobID] });
    expect(JSON.parse(String(originalRow.rows[0]?.request_json))).toMatchObject({ payload: { sodapush: { localNotification: { ...command, identifier: createdBody.localNotificationIdentifier } } } });
    expect(queued).toEqual([{ jobID: createdBody.jobID }]);

    await client.execute({ sql: "UPDATE push_jobs SET status='completed',success_count=1,total_count=1 WHERE id=?", args: [createdBody.jobID] });
    await client.execute({ sql: "INSERT INTO deliveries(id,job_id,device_id,status,created_at,updated_at) VALUES(?,?,?,?,?,?)", args: ["generated-id-delivery", createdBody.jobID, "device-1", "sent", "now", "now"] });
    const cancelled = await request(`/v1/apps/${appID}/pushes/${createdBody.jobID}/cancel-local`, { method: "POST", headers: authorization });
    expect(cancelled.status).toBe(202);
    const cancellationID = (await cancelled.json() as { jobID: string }).jobID;
    const cancellationRow = await client.execute({ sql: "SELECT request_json FROM push_jobs WHERE id=?", args: [cancellationID] });
    expect(JSON.parse(String(cancellationRow.rows[0]?.request_json))).toMatchObject({ payload: { sodapush: { localNotification: { action: "cancel", identifier: createdBody.localNotificationIdentifier } } } });

    const explicit = await request(`/v1/apps/${appID}/pushes`, { method: "POST", headers: authorization, body: JSON.stringify({ ...requestBody, payload: { ...requestBody.payload, sodapush: { version: 1, localNotification: { ...command, identifier: "existing-client-id" } } } }) });
    expect(explicit.status).toBe(202);
    expect((await explicit.json() as { localNotificationIdentifier: string }).localNotificationIdentifier).toBe("existing-client-id");
  });

  it("recalls queued alerts locally and delivered alerts through a background job", async () => {
    const { appID, accessToken } = await createApplication();
    const authorization = { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" };
    const queued: Array<{ jobID: string }> = [];
    env.PUSH_QUEUE = { send: async (body: { jobID: string }) => { queued.push(body); } } as unknown as Queue;
    const pushBody = { environment: "production", pushType: "alert", target: { all: true }, payload: { aps: { alert: "Recall me" } } };

    const scheduled = await request(`/v1/apps/${appID}/pushes/schedule`, { method: "POST", headers: authorization, body: JSON.stringify({ ...pushBody, scheduledAt: new Date(Date.now() + 60_000).toISOString() }) });
    expect(scheduled.status).toBe(202);
    const scheduledID = (await scheduled.json() as { jobID: string }).jobID;
    const storedSchedule = await client.execute({ sql: "SELECT request_json FROM push_jobs WHERE id=?", args: [scheduledID] });
    expect(JSON.parse(String(storedSchedule.rows[0]?.request_json))).toMatchObject({ recallIdentifier: scheduledID });
    const stopped = await request(`/v1/apps/${appID}/pushes/${scheduledID}/recall`, { method: "POST", headers: authorization });
    expect(stopped.status).toBe(202);
    expect((await stopped.json() as { recallJobID: string | null }).recallJobID).toBeNull();
    await processPushJob(env, scheduledID);
    expect((await client.execute({ sql: "SELECT status,recalled_at FROM push_jobs WHERE id=?", args: [scheduledID] })).rows[0]).toMatchObject({ status: "queued", recalled_at: expect.any(String) });
    expect((await request(`/v1/apps/${appID}/pushes/${scheduledID}`, { headers: authorization }).then((response) => response.json()) as { push: { status: string } }).push.status).toBe("recalled");
    expect((await request(`/v1/apps/${appID}/pushes/${scheduledID}/recall`, { method: "POST", headers: authorization })).status).toBe(409);

    const sent = await request(`/v1/apps/${appID}/pushes`, { method: "POST", headers: authorization, body: JSON.stringify(pushBody) });
    expect(sent.status).toBe(202);
    const sentID = (await sent.json() as { jobID: string }).jobID;
    await client.execute({ sql: "UPDATE push_jobs SET status='completed',success_count=1,total_count=1 WHERE id=?", args: [sentID] });
    await client.execute({ sql: "INSERT INTO deliveries(id,job_id,device_id,status,created_at,updated_at) VALUES(?,?,?,?,?,?)", args: ["sent-for-recall", sentID, "device-1", "sent", "now", "now"] });
    env.PUSH_QUEUE = undefined;
    expect((await request(`/v1/apps/${appID}/pushes/${sentID}/recall`, { method: "POST", headers: authorization })).status).toBe(503);
    env.PUSH_QUEUE = { send: async () => { throw new Error("Queue unavailable"); } } as unknown as Queue;
    expect((await request(`/v1/apps/${appID}/pushes/${sentID}/recall`, { method: "POST", headers: authorization })).status).toBe(500);
    expect((await client.execute({ sql: "SELECT recalled_at,recall_job_id FROM push_jobs WHERE id=?", args: [sentID] })).rows[0]).toMatchObject({ recalled_at: null, recall_job_id: null });
    expect((await client.execute({ sql: "SELECT COUNT(*) AS count FROM push_jobs WHERE app_id=?", args: [appID] })).rows[0]?.count).toBe(2);
    env.PUSH_QUEUE = { send: async (body: { jobID: string }) => { queued.push(body); } } as unknown as Queue;
    const recall = await request(`/v1/apps/${appID}/pushes/${sentID}/recall`, { method: "POST", headers: authorization });
    expect(recall.status).toBe(202);
    const recallJobID = (await recall.json() as { recallJobID: string }).recallJobID;
    expect(queued.at(-1)).toEqual({ jobID: recallJobID });
    const recallRow = await client.execute({ sql: "SELECT request_json FROM push_jobs WHERE id=?", args: [recallJobID] });
    expect(JSON.parse(String(recallRow.rows[0]?.request_json))).toMatchObject({ recallOf: sentID, recallIdentifier: sentID, payload: { sodapush: { recallNotification: { identifier: sentID } } } });
    expect((await request(`/v1/apps/${appID}/pushes/${sentID}/delete`, { method: "POST", headers: authorization })).status).toBe(409);
  });

  it("does not guess an identifier for alerts created before recall support", async () => {
    const { appID, accessToken } = await createApplication();
    await client.execute({
      sql: "INSERT INTO push_jobs(id,app_id,environment,request_json,status,success_count,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
      args: ["legacy-alert", appID, "production", JSON.stringify({ pushType: "alert", target: { all: true }, payload: { aps: { alert: "Old" } } }), "completed", 1, "now", "now"],
    });

    const response = await request(`/v1/apps/${appID}/pushes/legacy-alert/recall`, { method: "POST", headers: { Authorization: `Bearer ${accessToken}` } });
    expect(response.status).toBe(409);
    expect((await response.json() as { code: string }).code).toBe("not_recallable");
    expect((await client.execute("SELECT recalled_at FROM push_jobs WHERE id='legacy-alert'")).rows[0]?.recalled_at).toBeNull();
  });

  it("keeps push history readable before the recall migration is applied", async () => {
    const { appID, accessToken } = await createApplication();
    await client.execute("ALTER TABLE push_jobs DROP COLUMN recalled_at");
    await client.execute("ALTER TABLE push_jobs DROP COLUMN recall_job_id");
    await client.execute({
      sql: "INSERT INTO push_jobs(id,app_id,environment,request_json,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
      args: ["pre-migration-alert", appID, "production", JSON.stringify({ pushType: "alert", target: { all: true }, payload: { aps: { alert: "Old" } } }), "completed", "now", "now"],
    });
    const authorization = { Authorization: `Bearer ${accessToken}` };
    const list = await request(`/v1/apps/${appID}/pushes`, { headers: authorization });
    expect(list.status).toBe(200);
    expect((await list.json() as { pushes: Array<{ id: string; recalledAt: string | null }> }).pushes).toMatchObject([{ id: "pre-migration-alert", recalledAt: null }]);
    const detail = await request(`/v1/apps/${appID}/pushes/pre-migration-alert`, { headers: authorization });
    expect(detail.status).toBe(200);
    expect((await detail.json() as { push: { id: string; recallJobID: string | null } }).push).toMatchObject({ id: "pre-migration-alert", recallJobID: null });
  });

  it("supports the practical management lifecycle without exposing stored secrets", async () => {
    const { appID, accessToken } = await createApplication();
    const authorization = { Authorization: `Bearer ${accessToken}` };

    const apps = await request("/v1/apps", { headers: authorization });
    expect((await apps.json() as { apps: Array<{ role: string }> }).apps[0]?.role).toBe("owner");

    const updated = await request(`/v1/apps/${appID}/update`, {
      method: "POST",
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
    const pushesBody = await pushes.json() as { pushes: Array<{ id: string; target: { all: boolean }; payload: { aps: { alert: string } } }> };
    expect(pushesBody.pushes[0]).toMatchObject({
      id: "job-1",
      target: { all: true },
      payload: { aps: { alert: "Hi" } },
    });
    const push = await request(`/v1/apps/${appID}/pushes/job-1`, { headers: authorization });
    const pushBody = await push.json() as { push: { failureCount: number; target: { all: boolean }; payload: { aps: { alert: string } } }; deliveries: Array<{ reason: string }> };
    expect(pushBody.push.failureCount).toBe(1);
    expect(pushBody.push.target).toEqual({ all: true });
    expect(pushBody.push.payload).toEqual({ aps: { alert: "Hi" } });
    expect(pushBody.deliveries[0]?.reason).toBe("Unregistered");

    const apns = await request(`/v1/apps/${appID}/apns-credentials`, {
      method: "POST",
      headers: { ...authorization, "Content-Type": "application/json" },
      body: JSON.stringify({ teamID: "TEAM123", keyID: "KEY123", p8: "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----", environment: "production", makeDefault: true }),
    });
    expect(apns.status).toBe(200);
    const apnsBody = await apns.json() as { credential: { id: string; environment: string; isDefault: boolean } };
    expect(apnsBody).not.toHaveProperty("credential.p8");
    expect(apnsBody.credential).toMatchObject({ environment: "production", isDefault: true });
    const credentials = await request(`/v1/apps/${appID}/apns-credentials`, { headers: authorization });
    expect(JSON.stringify(await credentials.json())).not.toContain("PRIVATE KEY");

    const targetedPush = await request(`/v1/apps/${appID}/pushes`, {
      method: "POST",
      headers: { ...authorization, "Content-Type": "application/json" },
      body: JSON.stringify({
        environment: "production",
        credentialID: apnsBody.credential.id,
        pushType: "alert",
        target: { tags: ["beta", "paid"] },
        payload: { aps: { alert: { title: "Hello", body: "World" } } },
      }),
    });
    expect(targetedPush.status).toBe(202);
    const targetedPushID = (await targetedPush.json() as { jobID: string }).jobID;
    const targetedDetail = await request(`/v1/apps/${appID}/pushes/${targetedPushID}`, { headers: authorization });
    expect((await targetedDetail.json() as { push: { credentialID: string; target: { tags: string[] }; payload: { aps: { alert: { title: string; body: string } } } } }).push)
      .toMatchObject({
        credentialID: apnsBody.credential.id,
        target: { tags: ["beta", "paid"] },
        payload: { aps: { alert: { title: "Hello", body: "World" } } },
      });

    const queuedMessages: Array<{ body: unknown; delaySeconds: number | undefined }> = [];
    env.PUSH_QUEUE = {
      send: async (body: unknown, options?: { delaySeconds?: number }) => {
        queuedMessages.push({ body, delaySeconds: options?.delaySeconds });
      },
    } as unknown as Queue;
    const requestedSchedule = new Date(Date.now() + 60_000).toISOString();
    const scheduledPush = await request(`/v1/apps/${appID}/pushes/schedule`, {
      method: "POST",
      headers: { ...authorization, "Content-Type": "application/json" },
      body: JSON.stringify({
        environment: "production",
        pushType: "alert",
        target: { all: true },
        payload: { aps: { alert: "Scheduled" } },
        scheduledAt: requestedSchedule,
      }),
    });
    expect(scheduledPush.status).toBe(202);
    const scheduledBody = await scheduledPush.json() as { jobID: string; status: string; scheduledAt: string };
    expect(scheduledBody).toMatchObject({ status: "queued", scheduledAt: requestedSchedule });
    expect(queuedMessages).toHaveLength(1);
    expect(queuedMessages[0]?.body).toEqual({ jobID: scheduledBody.jobID });
    expect(queuedMessages[0]?.delaySeconds).toBeGreaterThanOrEqual(59);
    expect(queuedMessages[0]?.delaySeconds).toBeLessThanOrEqual(60);
    const scheduledDetail = await request(`/v1/apps/${appID}/pushes/${scheduledBody.jobID}`, { headers: authorization });
    expect((await scheduledDetail.json() as { push: { scheduledAt: string } }).push.scheduledAt).toBe(requestedSchedule);

    const scheduleBody = {
      environment: "production",
      pushType: "alert",
      target: { all: true },
      payload: { aps: { alert: "Scheduled" } },
    };
    const missingDate = await request(`/v1/apps/${appID}/pushes/schedule`, {
      method: "POST",
      headers: { ...authorization, "Content-Type": "application/json" },
      body: JSON.stringify(scheduleBody),
    });
    expect(missingDate.status).toBe(400);
    expect(queuedMessages).toHaveLength(1);

    const invalidDate = await request(`/v1/apps/${appID}/pushes/schedule`, {
      method: "POST",
      headers: { ...authorization, "Content-Type": "application/json" },
      body: JSON.stringify({ ...scheduleBody, scheduledAt: "tomorrow" }),
    });
    expect(invalidDate.status).toBe(400);
    expect(queuedMessages).toHaveLength(1);

    env.PUSH_QUEUE = undefined;
    const unavailableQueue = await request(`/v1/apps/${appID}/pushes/schedule`, {
      method: "POST",
      headers: { ...authorization, "Content-Type": "application/json" },
      body: JSON.stringify({ ...scheduleBody, scheduledAt: requestedSchedule }),
    });
    expect(unavailableQueue.status).toBe(503);
    expect((await unavailableQueue.json() as { code: string }).code).toBe("queue_unavailable");

    const tooFarSchedule = await request(`/v1/apps/${appID}/pushes`, {
      method: "POST",
      headers: { ...authorization, "Content-Type": "application/json" },
      body: JSON.stringify({
        environment: "production",
        pushType: "alert",
        target: { all: true },
        payload: { aps: { alert: "Too far" } },
        scheduledAt: new Date(Date.now() + 86_500_000).toISOString(),
      }),
    });
    expect(tooFarSchedule.status).toBe(400);
    expect((await tooFarSchedule.json() as { code: string }).code).toBe("invalid_schedule");

    const extraOwner = await request("/v1/users", {
      method: "POST",
      headers: { ...authorization, "Content-Type": "application/json" },
      body: JSON.stringify({ username: "second-owner", password: "another-secure-password", role: "owner" }),
    });
    expect(extraOwner.status).toBe(400);

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
    const editedUser = await request(`/v1/users/${developerID}/update`, {
      method: "POST",
      headers: { ...authorization, "Content-Type": "application/json" },
      body: JSON.stringify({ username: "renamed-developer", password: "updated-secure-password" }),
    });
    expect(editedUser.status).toBe(200);
    expect((await editedUser.json() as { user: { username: string } }).user.username).toBe("renamed-developer");
    expect((await request("/v1/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "developer", password: "another-secure-password" }),
    })).status).toBe(401);

    const candidates = await request(`/v1/apps/${appID}/member-candidates`, { headers: authorization });
    expect((await candidates.json() as { users: Array<{ id: string }> }).users.map((candidate) => candidate.id)).toContain(developerID);
    const membership = await request(`/v1/apps/${appID}/members/${developerID}`, {
      method: "POST",
      headers: { ...authorization, "Content-Type": "application/json" },
      body: JSON.stringify({ role: "developer" }),
    });
    expect(membership.status).toBe(200);
    expect((await membership.json() as { member: { role: string } }).member.role).toBe("developer");

    const developerLogin = await request("/v1/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "renamed-developer", password: "updated-secure-password" }),
    });
    expect(developerLogin.status).toBe(200);
    const developerToken = (await developerLogin.json() as { accessToken: string }).accessToken;
    const rejectedPasswordChange = await request(`/v1/users/${developerID}/update`, {
      method: "POST",
      headers: { Authorization: `Bearer ${developerToken}`, "Content-Type": "application/json" },
      body: JSON.stringify({ password: "self-service-password", currentPassword: "wrong-password" }),
    });
    expect(rejectedPasswordChange.status).toBe(400);
    const selfUpdate = await request(`/v1/users/${developerID}/update`, {
      method: "POST",
      headers: { Authorization: `Bearer ${developerToken}`, "Content-Type": "application/json" },
      body: JSON.stringify({ username: "self-renamed", password: "self-service-password", currentPassword: "updated-secure-password" }),
    });
    expect(selfUpdate.status).toBe(200);
    const forbiddenUpdate = await request(`/v1/apps/${appID}/update`, {
      method: "POST",
      headers: { Authorization: `Bearer ${developerToken}`, "Content-Type": "application/json" },
      body: JSON.stringify({ name: "Not Allowed" }),
    });
    expect(forbiddenUpdate.status).toBe(403);

    const lastOwner = await request(`/v1/users/${(await client.execute("SELECT id FROM users WHERE role='owner'")).rows[0]?.id}/update`, {
      method: "POST",
      headers: { ...authorization, "Content-Type": "application/json" },
      body: JSON.stringify({ disabled: true }),
    });
    expect(lastOwner.status).toBe(409);
    expect((await lastOwner.json() as { code: string }).code).toBe("owner_immutable");

    const deletedPush = await request(`/v1/apps/${appID}/pushes/job-1/delete`, { method: "POST", headers: authorization });
    expect(deletedPush.status).toBe(204);
    expect((await client.execute({ sql: "SELECT COUNT(*) AS count FROM deliveries WHERE job_id=?", args: ["job-1"] })).rows[0]?.count).toBe(0);

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
