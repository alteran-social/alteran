import { expect } from '@std/expect';
import { describe, it } from './helpers/bdd';
import { makeEnv } from './helpers/env';
import { createAccount } from '../src/db/account';

type TestEnv = Awaited<ReturnType<typeof makeEnv>>;
const FIRST = 'did:example:first', SECOND = 'did:example:second';
const valid = (value: unknown): value is string => typeof value === 'string' && /^[0-9a-f]{32}$/.test(value);
async function incarnation(env: TestEnv, did: string): Promise<string | null> {
  return (await env.ALTERAN_DB.prepare('SELECT space_incarnation FROM account WHERE did = ?').bind(did)
    .first<{space_incarnation: string | null}>())?.space_incarnation ?? null;
}
async function insert(env: TestEnv, did: string, handle: string, mode = '') {
  return await env.ALTERAN_DB.prepare(`INSERT ${mode} INTO account (did, handle, created_at, updated_at) VALUES (?, ?, 1, 1)`)
    .bind(did, handle).run();
}
async function rejected(action: () => Promise<unknown>) {
  let failed = false;
  try { await action(); } catch { failed = true; }
  expect(failed).toBe(true);
}
async function count(env: TestEnv, table: string): Promise<number> {
  return (await env.ALTERAN_DB.prepare(`SELECT count(*) AS n FROM ${table}`).first<{n: number}>())!.n;
}

describe('account Space incarnation', () => {
  it('generates a valid incarnation, retains it on update/upsert, and rotates after deletion or replacement', async () => {
    const env = await makeEnv();
    expect(await createAccount(env, { did: FIRST, handle: 'first.example', passwordScrypt: null })).toBe(true);
    const original = await incarnation(env, FIRST);
    expect(valid(original)).toBe(true);
    await env.ALTERAN_DB.prepare('UPDATE account SET email = ? WHERE did = ?').bind('x@example.test', FIRST).run();
    await env.ALTERAN_DB.prepare(`INSERT INTO account (did, handle, created_at, updated_at) VALUES (?, ?, 1, 1)
      ON CONFLICT(did) DO UPDATE SET handle = excluded.handle, updated_at = excluded.updated_at`).bind(FIRST, 'changed.example').run();
    expect(await incarnation(env, FIRST)).toBe(original);
    await insert(env, FIRST, 'changed.example', 'OR IGNORE');
    expect(await incarnation(env, FIRST)).toBe(original);
    await rejected(() => env.ALTERAN_DB.prepare('UPDATE account SET did = ? WHERE did = ?').bind(SECOND, FIRST).run());
    await rejected(() => env.ALTERAN_DB.prepare('UPDATE account SET space_incarnation = NULL WHERE did = ?').bind(FIRST).run());
    await rejected(() => env.ALTERAN_DB.prepare('UPDATE account SET space_incarnation = ? WHERE did = ?').bind('a'.repeat(32), FIRST).run());
    await env.ALTERAN_DB.prepare('DELETE FROM account WHERE did = ?').bind(FIRST).run();
    await insert(env, FIRST, 'first.example');
    const recreated = await incarnation(env, FIRST);
    expect(valid(recreated)).toBe(true);
    expect(recreated).not.toBe(original);
    await insert(env, FIRST, 'first.example', 'OR REPLACE');
    const replaced = await incarnation(env, FIRST);
    expect(valid(replaced)).toBe(true);
    expect(replaced).not.toBe(recreated);
    expect(await count(env, 'account_space_incarnation_init')).toBe(0);
  });
  it('rotates on conflicting-handle REPLACE and rejects caller-supplied incarnations', async () => {
    const env = await makeEnv();
    await insert(env, FIRST, 'first.example'); await insert(env, SECOND, 'second.example');
    const first = await incarnation(env, FIRST), second = await incarnation(env, SECOND);
    await insert(env, SECOND, 'first.example', 'OR REPLACE');
    const replacement = await incarnation(env, SECOND);
    expect(await incarnation(env, FIRST)).toBeNull();
    expect(valid(replacement)).toBe(true);
    expect(replacement).not.toBe(first);
    expect(replacement).not.toBe(second);
    for (const supplied of ['a'.repeat(32), 'a'.repeat(32) + '\0tail', '', 'G'.repeat(32)]) {
      await rejected(() => env.ALTERAN_DB.prepare('INSERT OR REPLACE INTO account (did, handle, created_at, updated_at, space_incarnation) VALUES (?, ?, 1, 1, ?)')
        .bind(SECOND, 'first.example', supplied).run());
      expect(await incarnation(env, SECOND)).toBe(replacement);
    }
    await rejected(() => env.ALTERAN_DB.prepare(`INSERT INTO account (did, handle, created_at, updated_at, space_incarnation)
      VALUES (?, ?, 1, 1, ?) ON CONFLICT(did) DO UPDATE SET handle = excluded.handle`)
      .bind(SECOND, 'first.example', 'b'.repeat(32)).run());
    expect(await incarnation(env, SECOND)).toBe(replacement);
  });
  it('serializes concurrent account creation and leaves no initializer behind', async () => {
    const env = await makeEnv();
    const results = await Promise.all([
      createAccount(env, { did: FIRST, handle: 'first.example', passwordScrypt: null }),
      createAccount(env, { did: FIRST, handle: 'first.example', passwordScrypt: null }),
    ]);
    expect(results.filter(Boolean)).toHaveLength(1);
    expect(results.filter((result) => !result)).toHaveLength(1);
    expect(valid(await incarnation(env, FIRST))).toBe(true);
    const dids = Array.from({ length: 8 }, (_, index) => `did:example:extra${index}`);
    await Promise.all(dids.map((did, index) => insert(env, did, `extra${index}.example`)));
    const values = await Promise.all(dids.map((did) => incarnation(env, did)));
    expect(values.every(valid)).toBe(true);
    expect(new Set(values).size).toBe(dids.length);
    expect(await count(env, 'account_space_incarnation_init')).toBe(0);
  });
  it('rolls back ignored initialization, rewritten attempt, recursive attempt, and ignored cleanup', async () => {
    const env = await makeEnv();
    const cases: [string, string][] = [
      ['skip_attempt', 'CREATE TRIGGER skip_attempt BEFORE INSERT ON account_space_incarnation_init BEGIN SELECT RAISE(IGNORE); END'],
      ['skip_account_update', 'CREATE TRIGGER skip_account_update BEFORE UPDATE OF space_incarnation ON account BEGIN SELECT RAISE(IGNORE); END'],
      ['rewrite_attempt', "CREATE TRIGGER rewrite_attempt AFTER INSERT ON account_space_incarnation_init BEGIN UPDATE account_space_incarnation_init SET incarnation = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'; END"],
      ['extra_attempt', 'CREATE TRIGGER extra_attempt AFTER INSERT ON account_space_incarnation_init BEGIN INSERT OR REPLACE INTO account_space_incarnation_init SELECT * FROM account_space_incarnation_init; END'],
      ['skip_attempt_delete', 'CREATE TRIGGER skip_attempt_delete BEFORE DELETE ON account_space_incarnation_init BEGIN SELECT RAISE(IGNORE); END'],
    ];
    for (const [name, sql] of cases) {
      await env.ALTERAN_DB.exec(sql);
      for (const mode of ['', 'OR IGNORE', 'OR REPLACE']) await rejected(() => insert(env, FIRST, 'first.example', mode));
      expect(await count(env, 'account')).toBe(0);
      expect(await count(env, 'account_space_incarnation_init')).toBe(0);
      await env.ALTERAN_DB.exec(`DROP TRIGGER ${name}`);
    }
    await insert(env, FIRST, 'first.example');
    expect(valid(await incarnation(env, FIRST))).toBe(true);
  });
  it('blocks a direct update of a corrupted NULL row and prevents collision under OR REPLACE', async () => {
    const env = await makeEnv();
    await insert(env, FIRST, 'first.example');
    const first = await incarnation(env, FIRST);
    await env.ALTERAN_DB.exec('DROP TRIGGER account_space_incarnation_created');
    await insert(env, SECOND, 'second.example');
    expect(await incarnation(env, SECOND)).toBeNull();
    await rejected(() => env.ALTERAN_DB.prepare('UPDATE account SET space_incarnation = ? WHERE did = ?').bind('a'.repeat(32), SECOND).run());
    const withNul = 'a'.repeat(32) + String.fromCharCode(0) + 'tail';
    expect(withNul.charCodeAt(32)).toBe(0);
    await rejected(() => env.ALTERAN_DB.prepare('INSERT INTO account_space_incarnation_init (id, did, incarnation) VALUES (1, ?, ?)')
      .bind(SECOND, withNul).run());
    await env.ALTERAN_DB.prepare('INSERT INTO account_space_incarnation_init (id, did, incarnation) VALUES (1, ?, ?)').bind(SECOND, first).run();
    await rejected(() => env.ALTERAN_DB.prepare('UPDATE OR REPLACE account SET space_incarnation = ? WHERE did = ?').bind(first, SECOND).run());
    expect(await incarnation(env, FIRST)).toBe(first);
    expect(await incarnation(env, SECOND)).toBeNull();
    await rejected(() => insert(env, 'did:example:third', 'third.example'));
  });
});
