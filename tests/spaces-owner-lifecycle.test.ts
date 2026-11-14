import { expect } from '@std/expect';
import { describe, it } from './helpers/bdd';
import { makeSpaceEnv, spaceOwner } from './helpers/space-env';
import { createAccount } from '../src/db/account';
import { setAccountState } from '../src/db/dal';
import { createLocalSpace, applySpaceWrites, getSpaceRecord } from '../src/db/space-store';
import { readSpaceRepoOps } from '../src/db/space-ops';
import { beginPersonalSpaceDeletion, getPersonalSpaceDeletion } from '../src/db/space-lifecycle-delete';
import { stepPersonalSpaceDeletion } from '../src/db/space-lifecycle-cleanup';
import { SPACE_GENESIS_EMPTY } from '../src/db/space-genesis-sql';
import { loadSpaceSnapshot, commitSpaceWrites } from '../src/db/space-mutation';
import { parseSpaceRef } from '../src/db/space-ref';
import { encodeRecordBlock } from '../src/services/repo/blockstore-ops';
import { createPersonalSpace } from '../src/db/space-lifecycle-create';
import { SpaceStorageError } from '../src/db/space-types';
import type { Env } from '../src/env';

const DID = 'did:example:test';
const SPACE = `at://${DID}/space/com.example.notes/owner-lifecycle`;
const EMPTY = `at://${DID}/space/com.example.notes/owner-empty`;
const COLLECTION = 'com.example.note';
const first = { action: 'create' as const, collection: COLLECTION, rkey: 'one',
  record: { $type: COLLECTION, text: 'private' } };

async function fixture() {
  const env = await makeSpaceEnv(), owner = await spaceOwner(env);
  await createLocalSpace(env, SPACE, owner);
  const commit = await applySpaceWrites(env, SPACE, DID, [first], owner);
  if (!commit) throw new Error('Missing commit');
  return { env, owner, rev: commit.rev };
}

async function replaceAccount(env: Env) {
  await env.ALTERAN_DB.prepare('DELETE FROM account WHERE did = ?').bind(DID).run();
  await env.ALTERAN_DB.prepare('DELETE FROM account_state WHERE did = ?').bind(DID).run();
  await createAccount(env, { did: DID, handle: 'test.example', passwordScrypt: null });
  await setAccountState(env, DID, { tag: 'active' });
  return spaceOwner(env);
}

const replaceInTrigger = `DELETE FROM account WHERE did = '${DID}';
  INSERT INTO account (did, handle, created_at, updated_at) VALUES ('${DID}', 'test.example', 0, 0);`;

describe('Space owner incarnation through lifecycle', () => {
  it('keeps old data unavailable to both an old and a replacement account', async () => {
    const { env, owner, rev } = await fixture();
    const replacement = await replaceAccount(env);
    expect(replacement).not.toBe(owner);
    for (const incarnation of [owner, replacement]) {
      expect(await getSpaceRecord(env, SPACE, DID, COLLECTION, 'one', incarnation)).toBeNull();
      await expect(readSpaceRepoOps(env, SPACE, DID, { since: rev }, incarnation)).rejects.toThrow();
      await expect(applySpaceWrites(env, SPACE, DID, [{
        action: 'update', collection: COLLECTION, rkey: 'one',
        record: { $type: COLLECTION, text: 'replacement' },
      }], incarnation)).rejects.toThrow();
      expect((await beginPersonalSpaceDeletion(env, SPACE, crypto.randomUUID(), incarnation)).tag).toBe('unsupported');
    }
    expect((await env.ALTERAN_DB.prepare('SELECT COUNT(*) AS n FROM space_record WHERE space_ref = ?')
      .bind(SPACE).first())?.n).toBe(1);
  });

  it('projects no prior-owner metadata or records while preparing a replacement write', async () => {
    const { env } = await fixture();
    const replacement = await replaceAccount(env), database = env.ALTERAN_DB;
    let observed: Array<{ results: unknown[] }> | undefined;
    const watched = { ...env, ALTERAN_DB: new Proxy(database, { get(target, key) {
      if (key === 'batch') return async (statements: Parameters<typeof database.batch>[0]) => {
        const result = await database.batch(statements);
        if (statements.length === 3) observed = result as Array<{ results: unknown[] }>;
        return result;
      };
      const value = Reflect.get(target, key, target);
      return typeof value === 'function' ? value.bind(target) : value;
    } }) };
    await expect(applySpaceWrites(watched, SPACE, DID, [first], replacement)).rejects.toThrow();
    if (!observed) throw new Error('Missing mutation snapshot result');
    expect(observed.map((result) => result.results)).toEqual([[], [], []]);
  });

  it('does not observe Space liveness after account replacement during conflict recovery', async () => {
    const { env, owner } = await fixture();
    const [cid, value] = await encodeRecordBlock({ $type: COLLECTION, text: 'loser' });
    const write = { action: 'update' as const, collection: COLLECTION, rkey: 'one', cid: cid.toString(), value, blobs: [] };
    const ref = parseSpaceRef(SPACE);
    const snapshot = await loadSpaceSnapshot(env, ref, DID, [write], owner);
    await applySpaceWrites(env, SPACE, DID, [{ action: 'update', collection: COLLECTION, rkey: 'one',
      record: { $type: COLLECTION, text: 'winner' } }], owner);
    const database = env.ALTERAN_DB;
    let replaced = false;
    const watched = { ...env, ALTERAN_DB: new Proxy(database, { get(target, key) {
      if (key === 'batch') return async (statements: Parameters<typeof database.batch>[0]) => {
        const result = await database.batch(statements);
        await replaceAccount(env);
        replaced = true;
        return result;
      };
      const value = Reflect.get(target, key, target);
      return typeof value === 'function' ? value.bind(target) : value;
    } }) };
    await expect(commitSpaceWrites(watched, ref, DID, [write], snapshot)).rejects.toThrow('Space owner is unavailable');
    expect(replaced).toBe(true);
    expect((await database.prepare('SELECT generation FROM space_repo WHERE space_ref = ?').bind(SPACE).first())?.generation).toBe(2);
  });

  it('does not reveal a replacement account Space during failed-creation recovery', async () => {
    const env = await makeSpaceEnv(), owner = await spaceOwner(env), database = env.ALTERAN_DB;
    let replaced = false;
    const watched = { ...env, ALTERAN_DB: new Proxy(database, { get(target, key) {
      if (key === 'batch') return () => Promise.reject(new Error('Injected creation failure'));
      if (key === 'prepare') return (sql: string) => {
        const statement = database.prepare(sql);
        if (!sql.includes('SELECT 1 AS existing FROM space')) return statement;
        return new Proxy(statement, { get(prepared, property) {
          if (property === 'bind') return (...values: Parameters<typeof prepared.bind>) => {
            const bound = prepared.bind(...values);
            return new Proxy(bound, { get(result, resultKey) {
              if (resultKey === 'first') return async () => {
                const replacement = await replaceAccount(env);
                await createPersonalSpace(env, SPACE, { $type: 'com.atproto.personalspace.policy' }, crypto.randomUUID(), replacement);
                replaced = true;
                return bound.first();
              };
              const value = Reflect.get(result, resultKey, result);
              return typeof value === 'function' ? value.bind(result) : value;
            } });
          };
          const value = Reflect.get(prepared, property, prepared);
          return typeof value === 'function' ? value.bind(prepared) : value;
        } });
      };
      const value = Reflect.get(target, key, target);
      return typeof value === 'function' ? value.bind(target) : value;
    } }) };
    await expect(createPersonalSpace(watched, SPACE, { $type: 'com.atproto.personalspace.policy' },
      crypto.randomUUID(), owner)).rejects.toThrow('Space creation is unavailable');
    expect(replaced).toBe(true);
    expect((await database.prepare('SELECT COUNT(*) AS n FROM space WHERE space_ref = ?').bind(SPACE).first())?.n).toBe(1);
  });

  it('distinguishes an owned collision from an unrelated creation failure', async () => {
    const env = await makeSpaceEnv(), owner = await spaceOwner(env);
    await createLocalSpace(env, SPACE, owner);
    try {
      await createPersonalSpace(env, SPACE, { $type: 'com.atproto.personalspace.policy' }, crypto.randomUUID(), owner);
      throw new Error('Expected an owned collision');
    } catch (error) {
      expect(error).toBeInstanceOf(SpaceStorageError);
      expect((error as SpaceStorageError).code).toBe('SpaceAlreadyExists');
    }
    const database = env.ALTERAN_DB, fault = new Error('private database failure');
    const watched = { ...env, ALTERAN_DB: new Proxy(database, { get(target, key) {
      if (key === 'batch') return () => Promise.reject(fault);
      const value = Reflect.get(target, key, target);
      return typeof value === 'function' ? value.bind(target) : value;
    } }) };
    try {
      await createPersonalSpace(watched, EMPTY, { $type: 'com.atproto.personalspace.policy' }, crypto.randomUUID(), owner);
      throw new Error('Expected an unavailable result');
    } catch (error) {
      expect(error).toBeInstanceOf(SpaceStorageError);
      expect((error as SpaceStorageError).code).toBe('SpaceEpochUnavailable');
      expect((error as Error & { cause: unknown }).cause).toBe(fault);
      expect(Object.keys(error as object)).not.toContain('cause');
    }
  });

  it('denies old and forged replacement handles after deletion starts, including an empty Space', async () => {
    const { env, owner } = await fixture();
    await createLocalSpace(env, EMPTY, owner);
    const pending = await beginPersonalSpaceDeletion(env, SPACE, crypto.randomUUID(), owner);
    const empty = await beginPersonalSpaceDeletion(env, EMPTY, crypto.randomUUID(), owner);
    if (pending.tag !== 'started' || empty.tag !== 'started') throw new Error('Missing deletion handle');
    const replacement = await replaceAccount(env);
    for (const handle of [pending.handle, empty.handle]) {
      for (const candidate of [handle, { ...handle, ownerIncarnation: replacement }]) {
        expect(await getPersonalSpaceDeletion(env, candidate)).toBeNull();
        expect((await stepPersonalSpaceDeletion(env, candidate, 0, crypto.randomUUID())).tag).toBe('unavailable');
      }
      await expect(env.ALTERAN_DB.prepare('UPDATE space_personal_deletion_job SET sequence = sequence + 1 WHERE nonce = ?')
        .bind(handle.nonce).run()).rejects.toThrow();
    }
    expect((await env.ALTERAN_DB.prepare('SELECT COUNT(*) AS n FROM space_record WHERE space_ref = ?')
      .bind(SPACE).first())?.n).toBe(1);
  });

  it('rolls back creation of a deletion job if its account changes within the transaction', async () => {
    const { env, owner } = await fixture();
    await env.ALTERAN_DB.prepare(`CREATE TRIGGER replace_owner_on_delete_job AFTER INSERT ON space_personal_deletion_job
      BEGIN ${replaceInTrigger} END`).run();
    expect((await beginPersonalSpaceDeletion(env, SPACE, crypto.randomUUID(), owner)).tag).toBe('unavailable');
    expect(await spaceOwner(env)).toBe(owner);
    expect((await env.ALTERAN_DB.prepare('SELECT COUNT(*) AS n FROM space_personal_deletion_job').first())?.n).toBe(0);
    expect((await env.ALTERAN_DB.prepare('SELECT deleted_at FROM space WHERE space_ref = ?').bind(SPACE).first())?.deleted_at).toBeNull();
  });

  it('rolls back record deletion and job progress if account ownership changes during cleanup', async () => {
    const { env, owner } = await fixture();
    const started = await beginPersonalSpaceDeletion(env, SPACE, crypto.randomUUID(), owner);
    if (started.tag !== 'started') throw new Error('Missing deletion handle');
    await env.ALTERAN_DB.prepare(`CREATE TRIGGER replace_owner_on_cleanup AFTER DELETE ON space_personal_deletion_attempt
      BEGIN ${replaceInTrigger} END`).run();
    expect((await stepPersonalSpaceDeletion(env, started.handle, 0, crypto.randomUUID())).tag).toBe('unavailable');
    expect(await spaceOwner(env)).toBe(owner);
    expect((await getPersonalSpaceDeletion(env, started.handle))?.sequence).toBe(0);
    expect((await env.ALTERAN_DB.prepare('SELECT COUNT(*) AS n FROM space_record WHERE space_ref = ?')
      .bind(SPACE).first())?.n).toBe(1);
  });

  it('rolls back a write if cleanup tombstones the Space after its earlier assertion', async () => {
    const { env, owner, rev } = await fixture();
    const nonce = crypto.randomUUID();
    await env.ALTERAN_DB.prepare(`CREATE TRIGGER tombstone_after_mutation AFTER DELETE ON space_mutation_attempt
      BEGIN
        INSERT INTO space_personal_deletion_job
          (nonce, space_ref, authority_did, epoch_id, status, phase, sequence,
            last_step_nonce, last_step_phase, last_step_count, created_at)
          SELECT '${nonce}', space_ref, repo_did, active_epoch_id, 'deleting', 'records', 0, NULL, NULL, 0, 1
          FROM space_repo WHERE space_ref = OLD.space_ref AND repo_did = OLD.repo_did;
        UPDATE space SET deleted_at = 1 WHERE space_ref = OLD.space_ref;
      END`).run();
    await expect(applySpaceWrites(env, SPACE, DID, [{ action: 'update', collection: COLLECTION, rkey: 'one',
      record: { $type: COLLECTION, text: 'changed' } }], owner)).rejects.toThrow('malformed JSON');
    expect((await env.ALTERAN_DB.prepare('SELECT rev FROM space_repo WHERE space_ref = ?').bind(SPACE).first())?.rev).toBe(rev);
    expect((await env.ALTERAN_DB.prepare('SELECT deleted_at FROM space WHERE space_ref = ?').bind(SPACE).first())?.deleted_at).toBeNull();
    expect((await env.ALTERAN_DB.prepare('SELECT COUNT(*) AS n FROM space_personal_deletion_job').first())?.n).toBe(0);
  });

  it('cannot adopt orphan operations when a first writer creates an epoch', async () => {
    const env = await makeSpaceEnv(), owner = await spaceOwner(env);
    await createLocalSpace(env, SPACE, owner);
    await env.ALTERAN_DB.exec('DROP TRIGGER space_op_fence_insert');
    await env.ALTERAN_DB.prepare('INSERT INTO space_op VALUES (?, ?, ?, 0, ?, ?, NULL, NULL)')
      .bind(SPACE, DID, '3n2a5tw2wd22l', COLLECTION, 'orphan').run();
    await expect(applySpaceWrites(env, SPACE, DID, [first], owner)).rejects.toThrow();
    expect((await env.ALTERAN_DB.prepare('SELECT COUNT(*) AS n FROM space_repo WHERE space_ref = ?')
      .bind(SPACE).first())?.n).toBe(0);
    expect((await env.ALTERAN_DB.prepare('SELECT COUNT(*) AS n FROM space_epoch WHERE space_ref = ?')
      .bind(SPACE).first())?.n).toBe(0);
  });

  it('retries simultaneous first writers without duplicating their epoch or effects', async () => {
    const env = await makeSpaceEnv(), owner = await spaceOwner(env);
    const foreign = 'at://did:example:remote/space/com.example.notes/concurrent';
    await Promise.all(['one', 'two'].map((rkey) => applySpaceWrites(env, foreign, DID, [{
      action: 'create', collection: COLLECTION, rkey, record: { $type: COLLECTION, text: rkey },
    }], owner)));
    for (const [table, count] of [['space_epoch', 1], ['space_record', 2], ['space_op', 2]] as const) {
      expect((await env.ALTERAN_DB.prepare(`SELECT COUNT(*) AS n FROM ${table} WHERE space_ref = ?`)
        .bind(foreign).first())?.n).toBe(count);
    }
    expect((await env.ALTERAN_DB.prepare('SELECT COUNT(*) AS n FROM space_mutation_attempt').first())?.n).toBe(0);
    expect((await env.ALTERAN_DB.prepare('SELECT COUNT(*) AS n FROM space_commit_assertion').first())?.n).toBe(0);
  });

  it('checks every first-writer history category through indexed owner probes', async () => {
    const env = await makeSpaceEnv();
    const plan = await env.ALTERAN_DB.prepare(`EXPLAIN QUERY PLAN
      WITH t AS MATERIALIZED (SELECT ? AS space_ref, ? AS repo_did)
      SELECT ${SPACE_GENESIS_EMPTY} FROM t`).bind(SPACE, DID).all<{ detail: string }>();
    const text = plan.results.map((row: { detail: string }) => row.detail).join('\n');
    for (const index of ['space_epoch_space_owner', 'space_record_version_space_owner_epoch',
      'space_snapshot_lease_owner_expiry', 'space_gc_attempt_owner', 'space_quarantine_job_owner_epoch',
      'space_mutation_attempt_owner', 'space_personal_deletion_attempt_owner']) {
      expect(text).toContain(index);
    }
    for (const index of ['sqlite_autoindex_space_repo_1', 'space_record_path_idx',
      'sqlite_autoindex_space_op_1', 'space_blob_usage_space_cid_idx',
      'space_personal_creation_attempt_space', 'space_personal_deletion_job_space']) {
      expect(text).toContain(index);
    }
  });
});
