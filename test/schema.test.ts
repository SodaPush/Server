import { readFile } from "node:fs/promises";
import { createClient } from "@libsql/client";
import { describe, expect, it } from "vitest";

describe("database schema", () => {
  it("supports owner membership and delivery idempotency", async () => {
    const db = createClient({ url: ":memory:" });
    const one = await readFile(new URL("../migrations/0001_initial.sql", import.meta.url), "utf8");
    const two = await readFile(new URL("../migrations/0002_accounts_pushes.sql", import.meta.url), "utf8");
    const three = await readFile(new URL("../migrations/0003_targeting_and_credentials.sql", import.meta.url), "utf8");
    await db.executeMultiple(`${one}\n${two}\n${three}`);
    await db.batch([
      { sql: "INSERT INTO apps(id,name,bundle_id,created_at) VALUES(?,?,?,?)", args: ["app", "App", "com.example.app", "now"] },
      { sql: "INSERT INTO users(id,username,password_hash,password_salt,role,created_at,updated_at) VALUES(?,?,?,?,?,?,?)", args: ["user", "owner", "hash", "salt", "owner", "now", "now"] },
      { sql: "INSERT INTO app_memberships(app_id,user_id,role,created_at) VALUES(?,?,?,?)", args: ["app", "user", "owner", "now"] },
      { sql: "INSERT INTO push_jobs(id,app_id,environment,request_json,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?)", args: ["job", "app", "development", "{}", "queued", "now", "now"] },
    ]);
    await db.execute({ sql: "INSERT INTO deliveries(id,job_id,device_id,status,created_at,updated_at) VALUES(?,?,?,?,?,?)", args: ["one", "job", "device", "sent", "now", "now"] });
    await expect(db.execute({ sql: "INSERT INTO deliveries(id,job_id,device_id,status,created_at,updated_at) VALUES(?,?,?,?,?,?)", args: ["two", "job", "device", "sent", "now", "now"] })).rejects.toThrow();
    expect((await db.execute("SELECT role FROM app_memberships")).rows[0]?.role).toBe("owner");
    await expect(db.execute({ sql: "INSERT INTO users(id,username,password_hash,password_salt,role,created_at,updated_at) VALUES(?,?,?,?,?,?,?)", args: ["owner-2", "owner-2", "hash", "salt", "owner", "now", "now"] })).rejects.toThrow();
    db.close();
  });
});
