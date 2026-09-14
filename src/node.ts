import { readFile } from "node:fs/promises";
import { serve } from "@hono/node-server";
import { createClient, type Client } from "@libsql/client";
import { app } from "./index";
import type { Env } from "./types";

class NodeStatement {
  private readonly client: Client;
  readonly sql: string;
  private args: unknown[] = [];

  get boundArgs(): unknown[] { return this.args; }

  constructor(client: Client, sql: string) { this.client = client; this.sql = sql; }
  bind(...args: unknown[]): NodeStatement { this.args = args; return this; }
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
}

class NodeDatabase {
  constructor(private readonly client: Client) {}
  prepare(sql: string): NodeStatement { return new NodeStatement(this.client, sql); }
  async batch(statements: NodeStatement[]): Promise<unknown> {
    return this.client.batch(statements.map((statement) => ({ sql: statement.sql, args: statement.boundArgs as never[] })) as never[]);
  }
}

const client = createClient({ url: process.env.SODAPUSH_DB_URL ?? "file:./data/sodapush.db" });
const database = new NodeDatabase(client);
const env = {
  SODAPUSH_DB: database,
  MASTER_KEY: process.env.MASTER_KEY ?? "",
  BOOTSTRAP_TOKEN: process.env.BOOTSTRAP_TOKEN,
  APP_VERSION: process.env.APP_VERSION ?? "0.1.0",
} as unknown as Env;

async function main() {
  if (!env.MASTER_KEY || !env.BOOTSTRAP_TOKEN) throw new Error("MASTER_KEY and BOOTSTRAP_TOKEN are required");
  const migration = await readFile(new URL("../migrations/0001_initial.sql", import.meta.url), "utf8");
  const accountMigration = await readFile(new URL("../migrations/0002_accounts_pushes.sql", import.meta.url), "utf8");
  await client.executeMultiple(`${migration}\n${accountMigration}`);
  const deviceColumns = await client.execute("PRAGMA table_info(devices)");
  if (!deviceColumns.rows.some((column) => column.name === "language")) {
    const targetingMigration = await readFile(new URL("../migrations/0003_targeting_and_credentials.sql", import.meta.url), "utf8");
    await client.executeMultiple(targetingMigration);
  }
  const port = Number(process.env.PORT ?? "8787");
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) throw new Error("PORT must be a valid TCP port");
  serve({ fetch: (request) => app.fetch(request, env), port }, (info) => {
    console.log(`SodaPush Node server listening on http://localhost:${info.port}`);
  });
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
