import { expect } from '@std/expect';
import * as dagCbor from '@ipld/dag-cbor';
import { describe, it } from './helpers/bdd';
import { makeEnv } from './helpers/env';
import { applySpaceWrites, createLocalSpace, getSpaceRecord } from '../src/db/space-store';
import { acquireSpaceSnapshot, releaseSpaceSnapshot } from '../src/db/space-snapshot';
import { pruneSpaceRecordVersionsPage } from '../src/db/space-version-gc';

const did = 'did:example:test';
const space = `at://${did}/space/com.example.notes/a`;
const otherSpace = `at://${did}/space/com.example.notes/b`;
const collection = 'com.example.note';
const pruneSpaceRecordVersions = async (...args: Parameters<typeof pruneSpaceRecordVersionsPage>) =>
  (await pruneSpaceRecordVersionsPage(...args)).pruned;

function write(action: 'create' | 'update', text: string) {
  return { action, collection, rkey: 'a', record: { $type: collection, text } };
}

describe('persistent space write fence', () => {
  it('blocks the pre-MVCC writer update and its record and operation effects', async () => {
    const env = await makeEnv();
    await createLocalSpace(env, space);
    const first = await applySpaceWrites(env, space, did, [write('create', 'old')]);
    const old = await env.ALTERAN_DB.prepare('SELECT rev, set_hash, generation, mutation_id FROM space_repo WHERE space_ref = ? AND repo_did = ?')
      .bind(space, did).first<{ rev: string; set_hash: number[]; generation: number; mutation_id: string }>();
    await expect(env.ALTERAN_DB.batch([
      env.ALTERAN_DB.prepare(
        `UPDATE space_repo SET rev = ?, set_hash = ?, generation = ?, mutation_id = ?
         WHERE space_ref = ? AND repo_did = ? AND generation = ? AND mutation_id = ?`,
      ).bind('3zzzzzzzzzzzz', new Uint8Array(2048), old!.generation + 1, crypto.randomUUID(),
        space, did, old!.generation, old!.mutation_id),
      env.ALTERAN_DB.prepare('DELETE FROM space_record WHERE space_ref = ? AND repo_did = ?').bind(space, did),
    ])).rejects.toThrow();
    const stored = await getSpaceRecord(env, space, did, collection, 'a');
    expect(dagCbor.decode(stored!.value)).toMatchObject({ text: 'old' });
    const head = await env.ALTERAN_DB.prepare('SELECT rev, generation, set_hash FROM space_repo WHERE space_ref = ? AND repo_did = ?')
      .bind(space, did).first<{ rev: string; generation: number; set_hash: number[] }>();
    expect(head?.rev).toBe(first!.rev);
    expect(head?.generation).toBe(first!.generation);
    expect(Uint8Array.from(head!.set_hash)).toEqual(first!.setHash);
  });

  it('blocks old initial inserts, direct record writes, replacement and key moves', async () => {
    const env = await makeEnv();
    await createLocalSpace(env, space);
    await createLocalSpace(env, otherSpace);
    await expect(env.ALTERAN_DB.prepare(
      `INSERT INTO space_repo (space_ref, repo_did, rev, set_hash, generation, mutation_id)
       VALUES (?, ?, ?, ?, 1, ?)`,
    ).bind(otherSpace, did, '3n2a5tw2wd22l', new Uint8Array(2048), crypto.randomUUID()).run()).rejects.toThrow();
    await applySpaceWrites(env, space, did, [write('create', 'old')]);
    for (const sql of [
      'UPDATE space_record SET cid = ? WHERE space_ref = ? AND repo_did = ?',
      'DELETE FROM space_record WHERE cid != ? AND space_ref = ? AND repo_did = ?',
      'UPDATE space_record SET space_ref = ? WHERE space_ref = ? AND repo_did = ?',
    ]) {
      await expect(env.ALTERAN_DB.prepare(sql).bind(otherSpace, space, did).run()).rejects.toThrow();
    }
    await expect(env.ALTERAN_DB.prepare(
      `INSERT OR REPLACE INTO space_record (space_ref, repo_did, collection, rkey, cid, value_cbor, repo_rev)
       SELECT space_ref, repo_did, collection, rkey, cid, value_cbor, repo_rev FROM space_record WHERE space_ref = ?`,
    ).bind(space).run()).rejects.toThrow();
    await expect(env.ALTERAN_DB.prepare(
      `INSERT OR REPLACE INTO space_repo (space_ref, repo_did, rev, set_hash, generation, mutation_id, active_epoch_id)
       SELECT space_ref, repo_did, rev, set_hash, generation, mutation_id, active_epoch_id FROM space_repo WHERE space_ref = ?`,
    ).bind(space).run()).rejects.toThrow();
    expect(dagCbor.decode((await getSpaceRecord(env, space, did, collection, 'a'))!.value)).toMatchObject({ text: 'old' });
    expect((await env.ALTERAN_DB.prepare('SELECT COUNT(*) AS count FROM space_repo WHERE space_ref = ?')
      .bind(otherSpace).first())?.count).toBe(0);
  });

  it('keeps attempts transaction-scoped and aborts if cleanup is skipped', async () => {
    const env = await makeEnv();
    await createLocalSpace(env, space);
    const first = await applySpaceWrites(env, space, did, [write('create', 'old')]);
    expect((await env.ALTERAN_DB.prepare('SELECT COUNT(*) AS count FROM space_mutation_attempt').first())?.count).toBe(0);
    await env.ALTERAN_DB.prepare(
      `CREATE TRIGGER skip_attempt_cleanup BEFORE DELETE ON space_mutation_attempt BEGIN SELECT RAISE(IGNORE); END`,
    ).run();
    await expect(applySpaceWrites(env, space, did, [write('update', 'new')])).rejects.toThrow();
    expect((await env.ALTERAN_DB.prepare('SELECT COUNT(*) AS count FROM space_mutation_attempt').first())?.count).toBe(0);
    expect(await env.ALTERAN_DB.prepare('SELECT rev, generation FROM space_repo WHERE space_ref = ? AND repo_did = ?')
      .bind(space, did).first()).toEqual({ rev: first!.rev, generation: first!.generation });
    expect(dagCbor.decode((await getSpaceRecord(env, space, did, collection, 'a'))!.value)).toMatchObject({ text: 'old' });
  });

  it('rolls back side effects from a trigger on the attempt insert', async () => {
    const env = await makeEnv();
    await createLocalSpace(env, space);
    const first = await applySpaceWrites(env, space, did, [write('create', 'old')]);
    await env.ALTERAN_DB.prepare(
      `CREATE TRIGGER disturb_attempt AFTER INSERT ON space_mutation_attempt
       BEGIN UPDATE space SET deleted_at = 1 WHERE space_ref = NEW.space_ref; END`,
    ).run();
    await expect(applySpaceWrites(env, space, did, [write('update', 'new')])).rejects.toThrow();
    expect((await env.ALTERAN_DB.prepare('SELECT deleted_at FROM space WHERE space_ref = ?').bind(space).first())?.deleted_at)
      .toBeNull();
    expect(await env.ALTERAN_DB.prepare('SELECT rev, generation FROM space_repo WHERE space_ref = ? AND repo_did = ?')
      .bind(space, did).first()).toEqual({ rev: first!.rev, generation: first!.generation });
    expect((await env.ALTERAN_DB.prepare('SELECT COUNT(*) AS count FROM space_mutation_attempt').first())?.count).toBe(0);
    expect((await env.ALTERAN_DB.prepare('SELECT COUNT(*) AS count FROM space_commit_assertion').first())?.count).toBe(0);
    await env.ALTERAN_DB.prepare('DROP TRIGGER disturb_attempt').run();
    await env.ALTERAN_DB.prepare(
      `CREATE TRIGGER skip_attempt BEFORE INSERT ON space_mutation_attempt BEGIN SELECT RAISE(IGNORE); END`,
    ).run();
    await expect(applySpaceWrites(env, space, did, [write('update', 'new')])).rejects.toThrow();
    expect(await env.ALTERAN_DB.prepare('SELECT rev, generation FROM space_repo WHERE space_ref = ? AND repo_did = ?')
      .bind(space, did).first()).toEqual({ rev: first!.rev, generation: first!.generation });
  });

  it('rejects key moves and replacements even with a matching winner marker', async () => {
    const env = await makeEnv();
    await createLocalSpace(env, space);
    await createLocalSpace(env, otherSpace);
    await applySpaceWrites(env, space, did, [write('create', 'old')]);
    const marker = () => [
      env.ALTERAN_DB.prepare(
        `INSERT INTO space_mutation_attempt (mutation_id, space_ref, repo_did, epoch_id, generation, rev, set_hash)
         SELECT mutation_id, space_ref, repo_did, active_epoch_id, generation, rev, set_hash FROM space_repo
         WHERE space_ref = ? AND repo_did = ?`,
      ).bind(space, did),
      env.ALTERAN_DB.prepare(
        `INSERT INTO space_commit_assertion (mutation_id, valid)
         SELECT mutation_id || ':won', 1 FROM space_repo WHERE space_ref = ? AND repo_did = ?`,
      ).bind(space, did),
    ];
    await expect(env.ALTERAN_DB.batch([
      ...marker(),
      env.ALTERAN_DB.prepare('UPDATE space_record SET space_ref = ? WHERE space_ref = ? AND repo_did = ?')
        .bind(otherSpace, space, did),
    ])).rejects.toThrow();
    await expect(env.ALTERAN_DB.batch([
      ...marker(),
      env.ALTERAN_DB.prepare(
        `INSERT OR REPLACE INTO space_record (space_ref, repo_did, collection, rkey, cid, value_cbor, repo_rev)
         SELECT space_ref, repo_did, collection, rkey, cid, value_cbor, repo_rev FROM space_record WHERE space_ref = ?`,
      ).bind(space),
    ])).rejects.toThrow();
    await expect(env.ALTERAN_DB.batch([
      ...marker(),
      env.ALTERAN_DB.prepare(
        `INSERT INTO space_op (space_ref, repo_did, rev, ordinal, collection, rkey, cid, prev)
         VALUES (?, ?, ?, 99, ?, 'other', NULL, NULL)`,
      ).bind(space, did, '3zzzzzzzzzzzz', collection),
    ])).rejects.toThrow();
    expect((await env.ALTERAN_DB.prepare('SELECT COUNT(*) AS count FROM space_mutation_attempt').first())?.count).toBe(0);
    expect((await env.ALTERAN_DB.prepare('SELECT COUNT(*) AS count FROM space_commit_assertion').first())?.count).toBe(0);
  });

  it('pins historical versions during pruning and rolls back a skipped GC cleanup', async () => {
    const env = await makeEnv();
    await createLocalSpace(env, space);
    await applySpaceWrites(env, space, did, [write('create', 'old')]);
    const lease = await acquireSpaceSnapshot(env, space, did);
    await applySpaceWrites(env, space, did, [write('update', 'new')]);
    expect(await pruneSpaceRecordVersions(env, space, did)).toBe(0);
    await releaseSpaceSnapshot(env, lease);
    await env.ALTERAN_DB.prepare(
      `CREATE TRIGGER skip_gc_cleanup BEFORE DELETE ON space_gc_attempt BEGIN SELECT RAISE(IGNORE); END`,
    ).run();
    await expect(pruneSpaceRecordVersions(env, space, did)).rejects.toThrow();
    expect((await env.ALTERAN_DB.prepare('SELECT COUNT(*) AS count FROM space_record_version WHERE space_ref = ?')
      .bind(space).first())?.count).toBe(2);
    expect((await env.ALTERAN_DB.prepare('SELECT COUNT(*) AS count FROM space_gc_attempt').first())?.count).toBe(0);
    await env.ALTERAN_DB.prepare('DROP TRIGGER skip_gc_cleanup').run();
    expect(await pruneSpaceRecordVersions(env, space, did)).toBe(1);
  });
});
