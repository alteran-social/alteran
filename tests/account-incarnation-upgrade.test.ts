import { expect } from '@std/expect';
import { Miniflare } from 'miniflare';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { D1Database } from '@cloudflare/workers-types';
import { describe, it } from './helpers/bdd';

const directory = join(import.meta.dirname!, '..', 'migrations');
const files = readdirSync(directory).filter((name) => name.endsWith('.sql')).sort();
const guards = files.find((name) => name.startsWith('0038_'))!;
async function statements(database: D1Database, filename: string) {
  return readFileSync(join(directory, filename), 'utf8').split('--> statement-breakpoint')
    .map((chunk) => chunk.trim()).filter(Boolean).map((sql) => database.prepare(sql.replace(/\n/g, ' ')));
}
async function apply(database: D1Database, filename: string) {
  await database.batch(await statements(database, filename));
}
async function databaseAt0037() {
  const mf = new Miniflare({ d1Databases: { DB: ':memory:' }, compatibilityDate: '2025-10-02',
    script: "export default { fetch: () => new Response('ok') }", modules: true });
  await mf.ready;
  const db = await mf.getD1Database('DB') as unknown as D1Database;
  for (const file of files.filter((name) => name < '0037')) await apply(db, file);
  await db.prepare("INSERT INTO account (did, handle, created_at, updated_at) VALUES ('did:example:a', 'a.example', 1, 1), ('did:example:b', 'b.example', 2, 2)").run();
  await apply(db, files.find((name) => name.startsWith('0037_'))!);
  return { db, dispose: () => mf.dispose() };
}
async function rejected(action: () => Promise<unknown>) {
  let failed = false;
  try { await action(); } catch { failed = true; }
  expect(failed).toBe(true);
}

describe('account Space incarnation migration', () => {
  it('backfills populated pre-0037 accounts, preserves their data, and installs guarded inserts', async () => {
    const { db, dispose } = await databaseAt0037();
    try {
      expect((await db.prepare('SELECT count(*) AS n FROM account WHERE space_incarnation IS NULL').first())?.n).toBe(2);
      await apply(db, guards);
      const rows = await db.prepare('SELECT did, handle, created_at, space_incarnation FROM account ORDER BY did').all<{did: string; handle: string; created_at: number; space_incarnation: string}>();
      expect(rows.results.map((row) => [row.did, row.handle, row.created_at])).toEqual([
        ['did:example:a', 'a.example', 1], ['did:example:b', 'b.example', 2],
      ]);
      expect(rows.results.every((row) => /^[0-9a-f]{32}$/.test(row.space_incarnation))).toBe(true);
      expect(rows.results[0].space_incarnation).not.toBe(rows.results[1].space_incarnation);
      await rejected(() => db.prepare('UPDATE account SET space_incarnation = ? WHERE did = ?').bind('a'.repeat(32), 'did:example:a').run());
      await db.prepare("INSERT INTO account (did,handle,created_at,updated_at) VALUES ('did:example:c','c.example',3,3)").run();
      expect((await db.prepare("SELECT length(space_incarnation) AS n FROM account WHERE did = 'did:example:c'").first())?.n).toBe(32);
      expect((await db.prepare('SELECT count(*) AS n FROM account_space_incarnation_init').first())?.n).toBe(0);
    } finally { await dispose(); }
  });
  it('rejects any preexisting incarnation, including valid-looking or NUL-suffixed values', async () => {
    const { db, dispose } = await databaseAt0037();
    try {
      for (const value of ['a'.repeat(32), 'a'.repeat(32) + '\0tail', 'G'.repeat(32), '']) {
        await db.prepare("UPDATE account SET space_incarnation = ? WHERE did = 'did:example:a'").bind(value).run();
        await rejected(() => apply(db, guards));
        expect((await db.prepare("SELECT space_incarnation FROM account WHERE did = 'did:example:a'").first())?.space_incarnation).toBe(value);
        expect((await db.prepare("SELECT space_incarnation FROM account WHERE did = 'did:example:b'").first())?.space_incarnation).toBeNull();
        await db.prepare("UPDATE account SET space_incarnation = NULL WHERE did = 'did:example:a'").run();
      }
      await apply(db, guards);
      expect((await db.prepare('SELECT count(*) AS n FROM account WHERE space_incarnation IS NULL').first())?.n).toBe(0);
    } finally { await dispose(); }
  });
  it('rolls back the whole 0038 migration batch if a later trigger installation fails', async () => {
    const { db, dispose } = await databaseAt0037();
    try {
      await db.exec('CREATE TRIGGER account_space_incarnation_created AFTER INSERT ON account BEGIN SELECT 1; END');
      await rejected(() => apply(db, guards));
      expect((await db.prepare('SELECT count(*) AS n FROM account WHERE space_incarnation IS NULL').first())?.n).toBe(2);
      expect((await db.prepare("SELECT count(*) AS n FROM sqlite_master WHERE type = 'trigger' AND name = 'account_space_incarnation_update'").first())?.n).toBe(0);
      await db.exec('DROP TRIGGER account_space_incarnation_created');
      await apply(db, guards);
      expect((await db.prepare('SELECT count(*) AS n FROM account WHERE space_incarnation IS NULL').first())?.n).toBe(0);
    } finally { await dispose(); }
  });
});
