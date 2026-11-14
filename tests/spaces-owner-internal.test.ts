import { expect } from '@std/expect';
import { describe, it } from './helpers/bdd';
import { makeSpaceEnv, spaceOwner } from './helpers/space-env';
import { createAccount } from '../src/db/account';
import { setAccountState } from '../src/db/dal';
import { applySpaceWrites, createLocalSpace } from '../src/db/space-store';
import { acquireSpaceSnapshot, readSpaceSnapshotPage, releaseSpaceSnapshot } from '../src/db/space-snapshot';
import { pruneSpaceRecordVersionsPage } from '../src/db/space-version-gc';
import { claimSpaceQuarantine, stepSpaceQuarantine } from '../src/db/space-quarantine';
import { activateSpaceQuarantine } from '../src/db/space-quarantine-activation';
import { streamSpaceRepoArchive } from '../src/services/space-repo-export';
import { readRepoStar } from '@atproto/space';
import type { Env } from '../src/env';

const DID = 'did:example:test';
const SPACE = `at://${DID}/space/com.example.notes/ownership`;
const COLLECTION = 'com.example.note';

async function fixture() {
  const env = await makeSpaceEnv();
  const owner = await spaceOwner(env);
  await createLocalSpace(env, SPACE, owner);
  await applySpaceWrites(env, SPACE, DID, [{
    action: 'create', collection: COLLECTION, rkey: 'one', record: { $type: COLLECTION, text: 'old' },
  }], owner);
  return { env, owner };
}

async function replaceAccount(env: Env) {
  await env.ALTERAN_DB.prepare('DELETE FROM account WHERE did = ?').bind(DID).run();
  await env.ALTERAN_DB.prepare('DELETE FROM account_state WHERE did = ?').bind(DID).run();
  await createAccount(env, { did: DID, handle: 'test.example', passwordScrypt: null });
  await setAccountState(env, DID, { tag: 'active' });
  return await spaceOwner(env);
}

const replaceInTrigger = `DELETE FROM account WHERE did = '${DID}';
  INSERT INTO account (did, handle, created_at, updated_at) VALUES ('${DID}', 'test.example', 0, 0);`;

describe('internal Space owner fences', () => {
  it('denies old and new incarnations access to a retained snapshot and version history', async () => {
    const { env, owner } = await fixture();
    const lease = await acquireSpaceSnapshot(env, SPACE, DID, owner);
    await applySpaceWrites(env, SPACE, DID, [{
      action: 'update', collection: COLLECTION, rkey: 'one', record: { $type: COLLECTION, text: 'new' },
    }], owner);
    const replacement = await replaceAccount(env);
    expect(replacement).not.toBe(owner);
    await expect(readSpaceSnapshotPage(env, lease, null)).rejects.toThrow();
    await expect(readSpaceSnapshotPage(env, { ...lease, ownerIncarnation: replacement }, null)).rejects.toThrow();
    await expect(acquireSpaceSnapshot(env, SPACE, DID, owner)).rejects.toThrow();
    await expect(acquireSpaceSnapshot(env, SPACE, DID, replacement)).rejects.toThrow();
    await expect(pruneSpaceRecordVersionsPage(env, SPACE, DID, owner)).rejects.toThrow();
    await expect(pruneSpaceRecordVersionsPage(env, SPACE, DID, replacement)).rejects.toThrow();
    await releaseSpaceSnapshot(env, { ...lease, token: crypto.randomUUID() });
    expect((await env.ALTERAN_DB.prepare('SELECT COUNT(*) AS n FROM space_snapshot_lease').first<{ n: number }>())?.n).toBe(1);
    await releaseSpaceSnapshot(env, lease);
    expect((await env.ALTERAN_DB.prepare('SELECT COUNT(*) AS n FROM space_snapshot_lease').first<{ n: number }>())?.n).toBe(0);
  });

  it('rolls back snapshot renewal when a trigger replaces the account', async () => {
    const { env, owner } = await fixture();
    const lease = await acquireSpaceSnapshot(env, SPACE, DID, owner);
    const before = await env.ALTERAN_DB.prepare('SELECT renewal_nonce FROM space_snapshot_lease WHERE id = ?')
      .bind(lease.id).first();
    await env.ALTERAN_DB.prepare(`CREATE TRIGGER replace_owner_on_renew AFTER UPDATE OF renewal_nonce ON space_snapshot_lease
      BEGIN ${replaceInTrigger} END`).run();
    await expect(readSpaceSnapshotPage(env, lease, null)).rejects.toThrow();
    expect(await spaceOwner(env)).toBe(owner);
    expect(await env.ALTERAN_DB.prepare('SELECT renewal_nonce FROM space_snapshot_lease WHERE id = ?')
      .bind(lease.id).first()).toEqual(before);
    await env.ALTERAN_DB.prepare('DROP TRIGGER replace_owner_on_renew').run();
    expect((await readSpaceSnapshotPage(env, lease, null)).records).toHaveLength(1);
    await releaseSpaceSnapshot(env, lease);
  });

  it('rolls back an ignored snapshot acquisition with an ownership side effect', async () => {
    const { env, owner } = await fixture();
    await env.ALTERAN_DB.prepare(`CREATE TRIGGER ignore_lease_with_replacement BEFORE INSERT ON space_snapshot_lease
      BEGIN ${replaceInTrigger} SELECT RAISE(IGNORE); END`).run();
    await expect(acquireSpaceSnapshot(env, SPACE, DID, owner)).rejects.toThrow();
    expect(await spaceOwner(env)).toBe(owner);
    expect((await env.ALTERAN_DB.prepare('SELECT COUNT(*) AS n FROM space_snapshot_lease').first<{ n: number }>())?.n).toBe(0);
  });

  it('rolls back quarantine claim if account ownership changes in its transaction', async () => {
    const { env, owner } = await fixture();
    await env.ALTERAN_DB.prepare("UPDATE space_epoch SET state = 'quarantined' WHERE space_ref = ?").bind(SPACE).run();
    await env.ALTERAN_DB.prepare(`CREATE TRIGGER replace_owner_on_claim AFTER INSERT ON space_quarantine_job
      BEGIN ${replaceInTrigger} END`).run();
    expect(await claimSpaceQuarantine(env, SPACE, DID, owner)).toBeNull();
    expect(await spaceOwner(env)).toBe(owner);
    expect((await env.ALTERAN_DB.prepare('SELECT COUNT(*) AS n FROM space_quarantine_job').first<{ n: number }>())?.n).toBe(0);
    await env.ALTERAN_DB.prepare('DROP TRIGGER replace_owner_on_claim').run();
    const handle = await claimSpaceQuarantine(env, SPACE, DID, owner);
    if (!handle) throw new Error('Missing quarantine handle');
    const replacement = await replaceAccount(env);
    expect(await stepSpaceQuarantine(env, handle)).toEqual({ tag: 'unavailable' });
    expect(await stepSpaceQuarantine(env, { ...handle, ownerIncarnation: replacement })).toEqual({ tag: 'unavailable' });
    expect(await activateSpaceQuarantine(env, handle)).toBe('unavailable');
    expect(await claimSpaceQuarantine(env, SPACE, DID, replacement)).toBeNull();
    await expect(env.ALTERAN_DB.prepare('UPDATE space_quarantine_job SET lease_until = unixepoch() + 1 WHERE id = ?')
      .bind(handle.id).run()).rejects.toThrow();
  });

  it('rolls back quarantine renewal when a trigger replaces the account', async () => {
    const { env, owner } = await fixture();
    await env.ALTERAN_DB.prepare("UPDATE space_epoch SET state = 'quarantined' WHERE space_ref = ?").bind(SPACE).run();
    const handle = await claimSpaceQuarantine(env, SPACE, DID, owner);
    if (!handle) throw new Error('Missing quarantine handle');
    const before = await env.ALTERAN_DB.prepare('SELECT renewal_nonce FROM space_quarantine_job WHERE id = ?')
      .bind(handle.id).first();
    await env.ALTERAN_DB.prepare(`CREATE TRIGGER replace_owner_on_job_renew AFTER UPDATE OF renewal_nonce ON space_quarantine_job
      BEGIN ${replaceInTrigger} END`).run();
    expect(await stepSpaceQuarantine(env, handle)).toEqual({ tag: 'unavailable' });
    expect(await spaceOwner(env)).toBe(owner);
    expect(await env.ALTERAN_DB.prepare('SELECT renewal_nonce FROM space_quarantine_job WHERE id = ?')
      .bind(handle.id).first()).toEqual(before);
    await env.ALTERAN_DB.exec('DROP TRIGGER replace_owner_on_job_renew');
    expect(await stepSpaceQuarantine(env, handle)).toEqual({ tag: 'progress', records: 1 });
  });

  it('does not report a completed or activated job to a replacement account', async () => {
    const { env, owner } = await fixture();
    await env.ALTERAN_DB.exec('DROP TRIGGER space_op_fence_delete');
    await env.ALTERAN_DB.exec('DROP TRIGGER space_op_owner_delete');
    await env.ALTERAN_DB.prepare('DELETE FROM space_op WHERE space_ref = ?').bind(SPACE).run();
    await env.ALTERAN_DB.prepare("UPDATE space_epoch SET state = 'quarantined' WHERE space_ref = ?").bind(SPACE).run();
    const handle = await claimSpaceQuarantine(env, SPACE, DID, owner);
    if (!handle) throw new Error('Missing quarantine handle');
    expect(await stepSpaceQuarantine(env, handle)).toEqual({ tag: 'progress', records: 1 });
    expect(await stepSpaceQuarantine(env, handle)).toEqual({ tag: 'complete', records: 1 });
    await env.ALTERAN_DB.exec('DROP TRIGGER space_epoch_quarantine_guard');
    expect(await activateSpaceQuarantine(env, handle)).toBe('active');
    const replacement = await replaceAccount(env);
    expect(await activateSpaceQuarantine(env, handle)).toBe('unavailable');
    expect(await activateSpaceQuarantine(env, { ...handle, ownerIncarnation: replacement })).toBe('unavailable');
  });

  it('does not reveal a failed verification receipt after account replacement', async () => {
    const { env, owner } = await fixture();
    await env.ALTERAN_DB.prepare("UPDATE space_epoch SET state = 'quarantined' WHERE space_ref = ?").bind(SPACE).run();
    const handle = await claimSpaceQuarantine(env, SPACE, DID, owner);
    if (!handle) throw new Error('Missing quarantine handle');
    await env.ALTERAN_DB.exec('DROP TRIGGER space_record_fence_update');
    await env.ALTERAN_DB.prepare("UPDATE space_record SET value_cbor = x'00' WHERE space_ref = ?").bind(SPACE).run();
    expect(await stepSpaceQuarantine(env, handle)).toEqual({ tag: 'invalid' });
    expect(await stepSpaceQuarantine(env, handle)).toEqual({ tag: 'invalid' });
    const replacement = await replaceAccount(env);
    expect(await stepSpaceQuarantine(env, handle)).toEqual({ tag: 'unavailable' });
    expect(await stepSpaceQuarantine(env, { ...handle, ownerIncarnation: replacement })).toEqual({ tag: 'unavailable' });
  });

  it('rejects malformed and unbound owners and mismatched Space metadata', async () => {
    const { env, owner } = await fixture();
    await expect(acquireSpaceSnapshot(env, SPACE, DID, `${owner}\0`)).rejects.toThrow();
    await expect(pruneSpaceRecordVersionsPage(env, SPACE, DID, 'A'.repeat(32))).rejects.toThrow();
    expect(await claimSpaceQuarantine(env, SPACE, DID, `${owner}\n`)).toBeNull();
    await env.ALTERAN_DB.exec('DROP TRIGGER space_epoch_owner_immutable');
    await env.ALTERAN_DB.prepare('UPDATE space_epoch SET owner_incarnation = NULL WHERE space_ref = ?').bind(SPACE).run();
    await expect(acquireSpaceSnapshot(env, SPACE, DID, owner)).rejects.toThrow();
    await expect(pruneSpaceRecordVersionsPage(env, SPACE, DID, owner)).rejects.toThrow();
  });

  it('does not treat a local Space without a bound personal policy as owned', async () => {
    const { env, owner } = await fixture();
    await env.ALTERAN_DB.exec('DROP TRIGGER space_personal_policy_delete');
    await env.ALTERAN_DB.prepare('DELETE FROM space_personal_policy WHERE space_ref = ?').bind(SPACE).run();
    await expect(acquireSpaceSnapshot(env, SPACE, DID, owner)).rejects.toThrow();
    await expect(pruneSpaceRecordVersionsPage(env, SPACE, DID, owner)).rejects.toThrow();
  });

  it('uses the local writer owner for foreign-authority Spaces and rejects inconsistent metadata', async () => {
    const env = await makeSpaceEnv();
    const owner = await spaceOwner(env);
    const foreignSpace = 'at://did:example:foreign/space/com.example.notes/remote';
    await applySpaceWrites(env, foreignSpace, DID, [{
      action: 'create', collection: COLLECTION, rkey: 'one', record: { $type: COLLECTION },
    }], owner);
    const lease = await acquireSpaceSnapshot(env, foreignSpace, DID, owner);
    expect((await readSpaceSnapshotPage(env, lease, null)).records).toHaveLength(1);
    await env.ALTERAN_DB.exec('DROP TRIGGER space_owner_space_update');
    await env.ALTERAN_DB.prepare('UPDATE space SET authority_did = ? WHERE space_ref = ?').bind(DID, foreignSpace).run();
    await expect(readSpaceSnapshotPage(env, lease, null)).rejects.toThrow();
    await releaseSpaceSnapshot(env, lease);
    const local = await fixture();
    await local.env.ALTERAN_DB.exec('DROP TRIGGER space_owner_space_update');
    await local.env.ALTERAN_DB.exec('DROP TRIGGER space_lifecycle_update');
    await local.env.ALTERAN_DB.prepare('UPDATE space SET authority_did = ? WHERE space_ref = ?')
      .bind('did:example:foreign', SPACE).run();
    await expect(acquireSpaceSnapshot(local.env, SPACE, DID, local.owner)).rejects.toThrow();
  });

  it('rolls back a version deletion when cleanup replaces the account', async () => {
    const { env, owner } = await fixture();
    await applySpaceWrites(env, SPACE, DID, [{
      action: 'update', collection: COLLECTION, rkey: 'one', record: { $type: COLLECTION, text: 'new' },
    }], owner);
    const database = env.ALTERAN_DB;
    let armed = false;
    const wrapped = new Proxy(database, {
      get(target, property) {
        if (property === 'batch') return async (statements: Parameters<typeof database.batch>[0]) => {
          const result = await database.batch(statements);
          if (!armed && statements.length === 6) {
            armed = true;
            await database.prepare(`CREATE TRIGGER replace_owner_after_gc AFTER DELETE ON space_gc_attempt
              BEGIN ${replaceInTrigger} END`).run();
          }
          return result;
        };
        const value = Reflect.get(target, property, target);
        return typeof value === 'function' ? value.bind(target) : value;
      },
    });
    await expect(pruneSpaceRecordVersionsPage({ ...env, ALTERAN_DB: wrapped }, SPACE, DID, owner)).rejects.toThrow();
    expect(armed).toBe(true);
    expect(await spaceOwner(env)).toBe(owner);
    expect((await database.prepare('SELECT COUNT(*) AS n FROM space_record_version WHERE until_generation IS NOT NULL')
      .first<{ n: number }>())?.n).toBe(1);
    expect((await database.prepare('SELECT COUNT(*) AS n FROM space_gc_attempt').first<{ n: number }>())?.n).toBe(0);
  });

  it('rolls back a GC attempt when its insertion replaces the account', async () => {
    const { env, owner } = await fixture();
    await applySpaceWrites(env, SPACE, DID, [{
      action: 'update', collection: COLLECTION, rkey: 'one', record: { $type: COLLECTION, text: 'new' },
    }], owner);
    await env.ALTERAN_DB.prepare(`CREATE TRIGGER replace_owner_on_gc AFTER INSERT ON space_gc_attempt
      BEGIN ${replaceInTrigger} END`).run();
    await expect(pruneSpaceRecordVersionsPage(env, SPACE, DID, owner)).rejects.toThrow();
    expect(await spaceOwner(env)).toBe(owner);
    expect((await env.ALTERAN_DB.prepare('SELECT COUNT(*) AS n FROM space_record_version WHERE until_generation IS NOT NULL')
      .first<{ n: number }>())?.n).toBe(1);
    expect((await env.ALTERAN_DB.prepare('SELECT COUNT(*) AS n FROM space_gc_attempt').first<{ n: number }>())?.n).toBe(0);
  });

  it('does not prune when account replacement occurs between GC scan and deletion', async () => {
    const { env, owner } = await fixture();
    await applySpaceWrites(env, SPACE, DID, [{
      action: 'update', collection: COLLECTION, rkey: 'one', record: { $type: COLLECTION, text: 'new' },
    }], owner);
    const database = env.ALTERAN_DB;
    let replaced = false;
    const wrapped = new Proxy(database, {
      get(target, property) {
        if (property === 'batch') return async (statements: Parameters<typeof database.batch>[0]) => {
          const result = await database.batch(statements);
          if (!replaced && statements.length === 6) {
            replaced = true;
            await replaceAccount(env);
          }
          return result;
        };
        const value = Reflect.get(target, property, target);
        return typeof value === 'function' ? value.bind(target) : value;
      },
    });
    await expect(pruneSpaceRecordVersionsPage({ ...env, ALTERAN_DB: wrapped }, SPACE, DID, owner)).rejects.toThrow();
    expect(replaced).toBe(true);
    expect((await database.prepare('SELECT COUNT(*) AS n FROM space_record_version WHERE until_generation IS NOT NULL')
      .first<{ n: number }>())?.n).toBe(1);
    expect((await database.prepare('SELECT COUNT(*) AS n FROM space_gc_attempt').first<{ n: number }>())?.n).toBe(0);
  });

  it('does not finish an export after the owner is replaced', async () => {
    const { env, owner } = await fixture();
    const stream = await streamSpaceRepoArchive(env, SPACE, DID, owner);
    await replaceAccount(env);
    await expect(new Response(stream.body).arrayBuffer()).rejects.toThrow();
    expect((await env.ALTERAN_DB.prepare('SELECT COUNT(*) AS n FROM space_snapshot_lease').first<{ n: number }>())?.n).toBe(0);
  });

  it('does not emit the archive footer when replacement follows a committed page', async () => {
    const { env, owner } = await fixture();
    const database = env.ALTERAN_DB;
    let replaced = false;
    const wrapped = new Proxy(database, {
      get(target, property) {
        if (property === 'batch') return async (statements: Parameters<typeof database.batch>[0]) => {
          const result = await database.batch(statements);
          if (!replaced && statements.length === 3) {
            replaced = true;
            await replaceAccount(env);
          }
          return result;
        };
        const value = Reflect.get(target, property, target);
        return typeof value === 'function' ? value.bind(target) : value;
      },
    });
    const stream = await streamSpaceRepoArchive({ ...env, ALTERAN_DB: wrapped }, SPACE, DID, owner);
    const chunks: Uint8Array[] = [];
    const reader = stream.body.getReader();
    await expect((async () => {
      for (;;) {
        const next = await reader.read();
        if (next.done) return;
        chunks.push(next.value);
      }
    })()).rejects.toThrow();
    expect(replaced).toBe(true);
    const partial = await readRepoStar(chunks);
    let records = 0;
    try {
      await expect((async () => { for await (const _record of partial.records) records++; })()).rejects.toThrow();
    } finally {
      await partial[Symbol.asyncDispose]();
    }
    expect(records).toBe(1);
    expect((await database.prepare('SELECT COUNT(*) AS n FROM space_snapshot_lease').first<{ n: number }>())?.n).toBe(0);
  });
});
