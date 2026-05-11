import { Miniflare } from "miniflare";
import { readdirSync, readFileSync } from "fs";
import { join } from "path";
import type { D1Database } from "@cloudflare/workers-types";
import type { Env } from "../../src/env";

const MIGRATIONS_DIR = join(import.meta.dir, "..", "..", "migrations");

// Drizzle separates statements with a literal "--> statement-breakpoint"
// sentinel. D1's exec() accepts a multi-statement string, but the in-memory
// runtime is happier when we feed statements one at a time.
function loadMigrationStatements(): string[] {
  const files = readdirSync(MIGRATIONS_DIR)
    .filter((name) => name.endsWith(".sql"))
    .sort();
  const statements: string[] = [];
  for (const file of files) {
    const sql = readFileSync(join(MIGRATIONS_DIR, file), "utf8");
    for (const chunk of sql.split("--> statement-breakpoint")) {
      const trimmed = chunk.trim();
      if (trimmed) statements.push(trimmed);
    }
  }
  return statements;
}

async function applyMigrations(database: D1Database): Promise<void> {
  for (const statement of loadMigrationStatements()) {
    await database.exec(statement.replace(/\n/g, " "));
  }
}

export async function makeEnv(overrides: Partial<Env> = {}): Promise<Env> {
  const mf = new Miniflare({
    d1Databases: { DB: ":memory:" },
    r2Buckets: ["BLOBS"],
    compatibilityDate: "2025-10-02",
    script: "export default { fetch: () => new Response('ok') }",
    modules: true,
    bindings: {
      PDS_DID: "did:example:test",
      PDS_HANDLE: "test.example",
      USER_PASSWORD: "pwd",
      REFRESH_TOKEN: "access-secret",
      REFRESH_TOKEN_SECRET: "refresh-secret",
      PDS_MAX_BLOB_SIZE: "5242880",
      PDS_ALLOWED_MIME: "image/png,image/jpeg",
    },
  });
  const DB = (await mf.getD1Database("DB")) as unknown as D1Database;
  const BLOBS = await mf.getR2Bucket("BLOBS");
  await applyMigrations(DB);
  return {
    DB,
    BLOBS,
    PDS_DID: "did:example:test",
    PDS_HANDLE: "test.example",
    USER_PASSWORD: "pwd",
    ...overrides,
  } as Env;
}

export const ctx = {
  waitUntil: (_p: Promise<any>) => {},
  passThroughOnException: () => {},
} as unknown as ExecutionContext;
