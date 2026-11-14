import { DatabaseSync } from 'node:sqlite';
import { join } from 'node:path';
import { expect } from '@std/expect';
import { applyPrivateBlobMigrations, disposePrivateBlobEnv, makePrivateBlobEnv } from './helpers/private-blob-env';

const ALPHA = 'did:example:alpha', BETA = 'did:example:beta', TYPE = 'com.example.notes';
const alphaSpace = `at://${ALPHA}/space/${TYPE}/legacy`;
const betaSpace = `at://${BETA}/space/${TYPE}/personal`;
const migrations = join(import.meta.dirname!, '..', 'migrations');

type SqlRow = { type: string; name: string; sql: string };
function quote(identifier: string): string { return `"${identifier.replaceAll('"', '""')}"`; }
function rejected(action: () => unknown) {
  let failed = false;
  try { action(); } catch { failed = true; }
  expect(failed).toBe(true);
}

function seed(database: DatabaseSync) {
  database.prepare('INSERT INTO account (did, handle, created_at, updated_at) VALUES (?, ?, 1, 1)').run(BETA, 'beta.example');
  database.prepare('INSERT INTO account_state (did, active, created_at) VALUES (?, 1, 1)').run(BETA);
  const account = database.prepare('SELECT space_incarnation FROM account WHERE did = ?').get(BETA) as { space_incarnation: string };
  const nonce = crypto.randomUUID();
  database.prepare('INSERT INTO space (rowid, space_ref, authority_did, space_type, skey, created_at) VALUES (2, ?, ?, ?, ?, 1)')
    .run(alphaSpace, ALPHA, TYPE, 'legacy');
  database.prepare(`INSERT INTO space_personal_creation_attempt
    (nonce, space_ref, authority_did, space_type, skey, created_at, authority_incarnation) VALUES (?, ?, ?, ?, ?, 1, ?)`)
    .run(nonce, betaSpace, BETA, TYPE, 'personal', account.space_incarnation);
  database.prepare('INSERT INTO space (rowid, space_ref, authority_did, space_type, skey, created_at) VALUES (3, ?, ?, ?, ?, 1)')
    .run(betaSpace, BETA, TYPE, 'personal');
  database.prepare(`INSERT INTO space_personal_policy
    (space_ref, authority_did, authority_incarnation, policy_type, creation_nonce, notification_state, created_at)
    VALUES (?, ?, ?, 'com.atproto.personalspace.policy', ?, 'none', 1)`)
    .run(betaSpace, BETA, account.space_incarnation, nonce);
  database.prepare('DELETE FROM space_personal_creation_attempt WHERE nonce = ?').run(nonce);
}

function logicalReload(source: DatabaseSync): DatabaseSync {
  const destination = new DatabaseSync(':memory:', { enableDoubleQuotedStringLiterals: true });
  const schema = source.prepare(`SELECT type, name, sql FROM sqlite_schema
    WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%' AND type IN ('table','index','view','trigger')`).all() as SqlRow[];
  for (const row of schema.filter((item) => item.type === 'table')) destination.exec(row.sql);
  for (const table of schema.filter((item) => item.type === 'table')) {
    const columns = source.prepare(`PRAGMA table_info(${quote(table.name)})`).all() as { name: string }[];
    const names = columns.map(({ name }) => name);
    const values = source.prepare(`SELECT ${names.map(quote).join(', ')} FROM ${quote(table.name)}`).all();
    const insert = destination.prepare(`INSERT INTO ${quote(table.name)} (${names.map(quote).join(', ')})
      VALUES (${names.map(() => '?').join(', ')})`);
    for (const row of values) insert.run(...names.map((name) => row[name]) as never[]);
  }
  for (const type of ['index', 'view', 'trigger']) {
    for (const row of schema.filter((item) => item.type === type)) destination.exec(row.sql);
  }
  return destination;
}

Deno.test('logical SQLite reload and rowid changes retain exact Space quarantine identity', async () => {
  const source = new DatabaseSync(':memory:', { enableDoubleQuotedStringLiterals: true });
  let destination: DatabaseSync | undefined;
  try {
    const names = Array.from(Deno.readDirSync(migrations)).map((entry) => entry.name).filter((name) => name.endsWith('.sql')).sort();
    for (const name of names.filter((name) => name < '0044')) source.exec(await Deno.readTextFile(join(migrations, name)));
    seed(source);
    const migration = names.find((name) => name.startsWith('0044_'));
    if (!migration) throw new Error('Missing listing migration');
    source.exec(await Deno.readTextFile(join(migrations, migration)));
    source.prepare('INSERT INTO space (space_ref,authority_did,space_type,skey,created_at) VALUES (?, ?, ?, ?, 1)')
      .run(new Uint8Array([0, 1, 2]), 'invalid', TYPE, 'bad');
    expect(source.prepare('SELECT COUNT(*) AS n FROM space_owner_quarantine_global').get()?.n).toBe(1);
    const oldRow = source.prepare('SELECT rowid AS id FROM space WHERE space_ref = ?').get(alphaSpace) as { id: number };
    expect(oldRow.id).toBe(2);
    destination = logicalReload(source);
    const newRow = destination.prepare('SELECT rowid AS id FROM space WHERE space_ref = ?').get(alphaSpace) as { id: number };
    expect(newRow.id).not.toBe(oldRow.id);
    const marker = destination.prepare('SELECT space_ref, authority_did FROM space_owner_unclassified').get();
    expect(marker).toMatchObject({ space_ref: alphaSpace, authority_did: ALPHA });
    expect(destination.prepare('SELECT COUNT(*) AS n FROM space_owner_unclassified WHERE space_ref = ?').get(betaSpace)?.n).toBe(0);
    rejected(() => destination!.prepare('DELETE FROM space_owner_unclassified WHERE space_ref = ?').run(alphaSpace));
    destination.prepare('UPDATE space SET rowid = 42 WHERE space_ref = ?').run(alphaSpace);
    expect(destination.prepare('SELECT COUNT(*) AS n FROM space_owner_unclassified WHERE space_ref = ?').get(alphaSpace)?.n).toBe(1);
    rejected(() => destination!.prepare('DELETE FROM space_owner_unclassified WHERE space_ref = ?').run(alphaSpace));
    destination.exec('DROP TRIGGER space_owner_space_delete');
    destination.prepare('DELETE FROM space WHERE space_ref = ?').run(alphaSpace);
    rejected(() => destination!.prepare('DELETE FROM space_owner_unclassified WHERE space_ref = ?').run(alphaSpace));
    rejected(() => destination!.prepare('INSERT INTO space (space_ref,authority_did,space_type,skey,created_at) VALUES (?,?,?,?,1)')
      .run(alphaSpace, ALPHA, TYPE, 'legacy'));
    expect(destination.prepare('SELECT COUNT(*) AS n FROM space_owner_unclassified WHERE space_ref = ?').get(alphaSpace)?.n).toBe(1);
    expect(destination.prepare('SELECT COUNT(*) AS n FROM space_owner_quarantine_global').get()?.n).toBe(1);
    rejected(() => destination!.exec('DELETE FROM space_owner_quarantine_global'));
    rejected(() => destination!.exec('UPDATE space_owner_quarantine_global SET id = 1'));
    rejected(() => destination!.exec('INSERT OR REPLACE INTO space_owner_quarantine_global (id) VALUES (1)'));
  } finally { destination?.close(); source.close(); }
});

Deno.test({
  name: 'local D1 rowid updates cannot retarget a Space quarantine marker',
  sanitizeOps: false, sanitizeResources: false,
  async fn() {
    const env = await makePrivateBlobEnv(43), database = env.ALTERAN_DB;
    try {
      await database.prepare('INSERT INTO space (rowid,space_ref,authority_did,space_type,skey,created_at) VALUES (2,?,?,?,?,1)')
        .bind(alphaSpace, ALPHA, TYPE, 'legacy').run();
      await applyPrivateBlobMigrations(database, 44, 44);
      await database.prepare('UPDATE space SET rowid = 42 WHERE space_ref = ?').bind(alphaSpace).run();
      const marker = await database.prepare('SELECT space_ref, authority_did FROM space_owner_unclassified').first();
      expect(marker).toEqual({ space_ref: alphaSpace, authority_did: ALPHA });
      let failed = false;
      try { await database.prepare('DELETE FROM space_owner_unclassified WHERE space_ref = ?').bind(alphaSpace).run(); }
      catch { failed = true; }
      expect(failed).toBe(true);
    } finally { await disposePrivateBlobEnv(); }
  },
});
