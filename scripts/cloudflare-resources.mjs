import { readFileSync, writeFileSync } from "node:fs";

const configPath = new URL("../wrangler.jsonc", import.meta.url);
const config = JSON.parse(readFileSync(configPath, "utf8"));
const database = config.d1_databases?.find((item) => item.binding === "SODAPUSH_DB");
if (!database?.database_name) throw new Error("SODAPUSH_DB binding is missing from wrangler.jsonc");

const [action, value] = process.argv.slice(2);
if (action === "database-name") {
  process.stdout.write(database.database_name);
} else if (action === "queue-names") {
  const names = new Set([
    ...config.queues?.producers?.map((item) => item.queue) ?? [],
    ...config.queues?.consumers?.flatMap((item) => [item.queue, item.dead_letter_queue].filter(Boolean)) ?? [],
  ]);
  process.stdout.write([...names].join("\n"));
} else if (action === "configure-d1") {
  if (!/^[0-9a-f-]{36}$/i.test(value ?? "")) throw new Error("Invalid D1 database ID");
  if (database.database_id !== value) {
    database.database_id = value;
    writeFileSync(configPath, `${JSON.stringify(config, null, 2)}\n`);
    console.log("Updated SODAPUSH_DB database_id in wrangler.jsonc.");
  }
} else if (action === "lookup-d1" || action === "has-queue") {
  let input = "";
  for await (const chunk of process.stdin) input += chunk;
  if (action === "lookup-d1") {
    const list = JSON.parse(input);
    if (!Array.isArray(list)) throw new Error("Unexpected Wrangler D1 list response");
    const matches = list.filter((item) => item.name === value);
    if (matches.length > 1) throw new Error(`Multiple D1 databases named ${value}`);
    process.stdout.write(matches[0]?.uuid ?? "");
  } else {
    const escaped = value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const row = new RegExp(`(?:^|\\s|│)${escaped}(?:$|\\s|│)`, "m");
    process.exit(row.test(input) ? 0 : 1);
  }
} else {
  throw new Error(`Unknown action: ${action}`);
}
