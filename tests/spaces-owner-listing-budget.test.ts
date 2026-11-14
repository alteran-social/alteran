import { expect } from '@std/expect';
import { afterEach, describe, it } from './helpers/bdd';
import { applyPrivateBlobMigrations, disposePrivateBlobEnv, makePrivateBlobEnv } from './helpers/private-blob-env';

async function rejected(action: () => Promise<unknown>) {
  let failed = false;
  try { await action(); } catch { failed = true; }
  expect(failed).toBe(true);
}

async function smallRows(database: Awaited<ReturnType<typeof makePrivateBlobEnv>>['ALTERAN_DB'], count: number) {
  await database.prepare(`WITH RECURSIVE numbered(value) AS (SELECT 1 UNION ALL SELECT value + 1 FROM numbered WHERE value < ?)
    INSERT INTO space (space_ref, authority_did, space_type, skey, created_at)
    SELECT 'at://did:example:legacy/space/com.example.notes/n' || value, 'did:example:legacy',
      'com.example.notes', 'n' || value, 1 FROM numbered`).bind(count).run();
}

const percentHeavyAuthority = `did:example:${'%61'.repeat(678)}x`;
async function percentHeavyRows(database: Awaited<ReturnType<typeof makePrivateBlobEnv>>['ALTERAN_DB'], count: number) {
  await database.prepare(`WITH RECURSIVE numbered(value) AS (SELECT 1 UNION ALL SELECT value + 1 FROM numbered WHERE value < ?)
    INSERT INTO space (space_ref, authority_did, space_type, skey, created_at)
    SELECT 'at://' || ? || '/space/com.example.notes/n' || value, ?, 'com.example.notes', 'n' || value, 1 FROM numbered`)
    .bind(count, percentHeavyAuthority, percentHeavyAuthority).run();
}

describe('Space listing migration budgets', () => {
  afterEach(disposePrivateBlobEnv);

  it('backfills the maximum row count on local D1', async () => {
    const env = await makePrivateBlobEnv(43), database = env.ALTERAN_DB;
    await smallRows(database, 4096);
    const start = performance.now();
    await applyPrivateBlobMigrations(database, 44, 44);
    const elapsed = Math.round(performance.now() - start);
    expect((await database.prepare('SELECT COUNT(*) AS n FROM space_owner_unclassified').first())?.n).toBe(4096);
    console.log(`Local D1 4096-row listing migration: ${elapsed} ms`);
  });

  it('leaves a populated database unchanged when the row cap is exceeded', async () => {
    const env = await makePrivateBlobEnv(43), database = env.ALTERAN_DB;
    await smallRows(database, 4097);
    const before = await database.prepare("SELECT COUNT(*) AS n FROM sqlite_master WHERE name LIKE 'space_owner_%'").first();
    await rejected(() => applyPrivateBlobMigrations(database, 44, 44));
    expect((await database.prepare('SELECT COUNT(*) AS n FROM space').first())?.n).toBe(4097);
    expect(await database.prepare("SELECT COUNT(*) AS n FROM sqlite_master WHERE name LIKE 'space_owner_%'").first()).toEqual(before);
    expect((await database.prepare("SELECT COUNT(*) AS n FROM sqlite_master WHERE name = 'space_owner_listing'").first())?.n).toBe(0);
  });

  it('leaves a populated database unchanged when the identity metadata budget is exceeded', async () => {
    const env = await makePrivateBlobEnv(43), database = env.ALTERAN_DB;
    await database.prepare(`WITH RECURSIVE numbered(value) AS (SELECT 1 UNION ALL SELECT value + 1 FROM numbered WHERE value < 1600)
      INSERT INTO space (space_ref, authority_did, space_type, skey, created_at)
      SELECT printf('%08d', value) || substr(hex(zeroblob(4092)), 1, 8184),
        substr(hex(zeroblob(1024)), 1, 2048), substr(hex(zeroblob(159)), 1, 317),
        substr(hex(zeroblob(256)), 1, 512), 1 FROM numbered`).run();
    await rejected(() => applyPrivateBlobMigrations(database, 44, 44));
    expect((await database.prepare('SELECT COUNT(*) AS n FROM space').first())?.n).toBe(1600);
    expect((await database.prepare("SELECT COUNT(*) AS n FROM sqlite_master WHERE name = 'space_owner_listing'").first())?.n).toBe(0);
  });

  it('classifies valid percent-heavy references just within the work budget', async () => {
    const env = await makePrivateBlobEnv(43), database = env.ALTERAN_DB;
    await smallRows(database, 4090);
    await percentHeavyRows(database, 6);
    const start = performance.now();
    await applyPrivateBlobMigrations(database, 44, 44);
    console.log(`Local D1 near-budget percent-heavy listing migration: ${Math.round(performance.now() - start)} ms`);
    const result = await database.prepare(`SELECT COUNT(*) AS count FROM space_owner_unclassified
      WHERE authority_did = ? AND space_type = 'com.example.notes'`).bind(percentHeavyAuthority).first();
    expect(result?.count).toBe(6);
    expect((await database.prepare('SELECT COUNT(*) AS n FROM space_owner_unclassified').first())?.n).toBe(4096);
    expect((await database.prepare('SELECT COUNT(*) AS n FROM space_owner_quarantine_global').first())?.n).toBe(0);
  });

  it('rejects excess percent-heavy work before changing a populated catalog', async () => {
    for (const count of [7, 512]) {
      const env = await makePrivateBlobEnv(43), database = env.ALTERAN_DB;
      await percentHeavyRows(database, count);
      const before = await database.prepare("SELECT COUNT(*) AS n FROM sqlite_master WHERE name LIKE 'space_owner_%'").first();
      const start = performance.now();
      await rejected(() => applyPrivateBlobMigrations(database, 44, 44));
      console.log(`Local D1 rejected ${count} percent-heavy rows: ${Math.round(performance.now() - start)} ms`);
      expect((await database.prepare('SELECT COUNT(*) AS n FROM space WHERE authority_did = ?').bind(percentHeavyAuthority).first())?.n)
        .toBe(count);
      expect(await database.prepare("SELECT COUNT(*) AS n FROM sqlite_master WHERE name LIKE 'space_owner_%'").first()).toEqual(before);
      expect((await database.prepare("SELECT COUNT(*) AS n FROM sqlite_master WHERE name = 'space_owner_listing'").first())?.n).toBe(0);
    }
  });
});
