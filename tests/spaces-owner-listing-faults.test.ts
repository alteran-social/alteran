import { expect } from '@std/expect';
import { describe, it } from './helpers/bdd';
import { makeSpaceEnv } from './helpers/space-env';
import { createPersonalSpace, applySpaceWrites, beginPersonalSpaceDeletion } from './helpers/space-storage';

const DID = 'did:example:test';
const SPACE = `at://${DID}/space/com.example.notes/faults`;
const POLICY = { $type: 'com.atproto.personalspace.policy' };
const FOREIGN = 'at://did:example:other/space/com.example.notes/foreign';

async function rejected(operation: () => Promise<unknown>) {
  let failed = false;
  try { await operation(); } catch { failed = true; }
  expect(failed).toBe(true);
}
async function count(env: Awaited<ReturnType<typeof makeSpaceEnv>>, table: string): Promise<number> {
  const row = await env.ALTERAN_DB.prepare(`SELECT COUNT(*) AS count FROM ${table}`).first<{ count: number }>();
  if (!row) throw new Error('Missing count');
  return row.count;
}

describe('Space listing catalog fences', () => {
  it('rolls back a personal create when Space or policy catalog effects are skipped', async () => {
    const env = await makeSpaceEnv();
    for (const [name, definition] of [
      ['skip_space_catalog', 'AFTER INSERT ON space'],
      ['skip_policy_catalog', 'AFTER INSERT ON space_personal_policy'],
      ['skip_marker_insert', 'BEFORE INSERT ON space_owner_unclassified'],
      ['skip_listing_insert', 'BEFORE INSERT ON space_owner_listing'],
      ['skip_marker_delete', 'BEFORE DELETE ON space_owner_unclassified'],
    ] as const) {
      await env.ALTERAN_DB.exec(`CREATE TRIGGER ${name} ${definition} BEGIN SELECT RAISE(IGNORE); END`);
      await rejected(() => createPersonalSpace(env, SPACE, POLICY, crypto.randomUUID()));
      expect(await count(env, 'space')).toBe(0);
      expect(await count(env, 'space_personal_policy')).toBe(0);
      expect(await count(env, 'space_owner_listing')).toBe(0);
      expect(await count(env, 'space_owner_unclassified')).toBe(0);
      await env.ALTERAN_DB.exec(`DROP TRIGGER ${name}`);
    }
    await createPersonalSpace(env, SPACE, POLICY, crypto.randomUUID());
    expect(await count(env, 'space_owner_listing')).toBe(1);
    expect(await count(env, 'space_owner_unclassified')).toBe(0);
  });

  it('rolls back a foreign Space mutation if its quarantine insertion is skipped', async () => {
    const env = await makeSpaceEnv();
    const writes = [{ action: 'create' as const, collection: 'com.example.note', rkey: 'one',
      record: { $type: 'com.example.note', text: 'one' } }];
    await env.ALTERAN_DB.exec('CREATE TRIGGER skip_foreign_catalog AFTER INSERT ON space BEGIN SELECT RAISE(IGNORE); END');
    await rejected(() => applySpaceWrites(env, FOREIGN, DID, writes));
    expect(await count(env, 'space')).toBe(0);
    expect(await count(env, 'space_repo')).toBe(0);
    expect(await count(env, 'space_owner_unclassified')).toBe(0);
    await env.ALTERAN_DB.exec('DROP TRIGGER skip_foreign_catalog');
    await applySpaceWrites(env, FOREIGN, DID, writes);
    expect(await count(env, 'space')).toBe(1);
    expect(await count(env, 'space_owner_unclassified')).toBe(1);
  });

  it('rolls back deletion if the active listing cannot be removed', async () => {
    const env = await makeSpaceEnv();
    await createPersonalSpace(env, SPACE, POLICY, crypto.randomUUID());
    for (const [name, definition] of [
      ['skip_listing_after_delete', 'AFTER UPDATE OF deleted_at ON space'],
      ['skip_listing_delete', 'BEFORE DELETE ON space_owner_listing'],
    ] as const) {
      await env.ALTERAN_DB.exec(`CREATE TRIGGER ${name} ${definition} BEGIN SELECT RAISE(IGNORE); END`);
      expect((await beginPersonalSpaceDeletion(env, SPACE, crypto.randomUUID())).tag).toBe('unavailable');
      expect(await count(env, 'space_personal_deletion_job')).toBe(0);
      expect(await count(env, 'space_owner_listing')).toBe(1);
      await env.ALTERAN_DB.exec(`DROP TRIGGER ${name}`);
    }
    expect((await beginPersonalSpaceDeletion(env, SPACE, crypto.randomUUID())).tag).toBe('started');
    expect(await count(env, 'space_owner_listing')).toBe(0);
  });
});
