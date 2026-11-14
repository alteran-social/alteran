import { expect } from '@std/expect';
import * as dagCbor from '@ipld/dag-cbor';
import { describe, it } from './helpers/bdd';
import { makeEnv } from './helpers/env';
import { applySpaceWrites, createLocalSpace, getSpaceRecord } from '../src/db/space-store';
import { applySpaceSetHashChanges, spaceRecordHashElement, spaceSetHashDigest } from '../src/lib/spaces/lthash';

const did = 'did:example:test';
const firstSpace = `at://${did}/space/com.example.notes/a`;
const collection = 'com.example.note';

function create(pathCollection: string, rkey: string, text: string) {
  return { action: 'create' as const, collection: pathCollection, rkey, record: { $type: pathCollection, text } };
}

function update(pathCollection: string, rkey: string, text: string) {
  return { action: 'update' as const, collection: pathCollection, rkey, record: { $type: pathCollection, text } };
}

describe('space commit transaction guards', () => {
  it('rolls back initialization when a trigger changes the winning head', async () => {
    const env = await makeEnv();
    await createLocalSpace(env, firstSpace);
    await env.ALTERAN_DB.prepare(
      `CREATE TRIGGER disturb_new_head AFTER INSERT ON space_repo
       BEGIN UPDATE space_repo SET mutation_id = 'changed' WHERE space_ref = NEW.space_ref AND repo_did = NEW.repo_did; END`,
    ).run();
    await expect(applySpaceWrites(env, firstSpace, did, [create(collection, 'a', 'private')])).rejects.toThrow();
    for (const table of ['space_repo', 'space_epoch', 'space_record', 'space_record_version', 'space_op', 'space_commit_assertion']) {
      expect((await env.ALTERAN_DB.prepare(`SELECT COUNT(*) AS count FROM ${table}`).first())?.count).toBe(0);
    }
  });

  it('rolls back a silently ignored initial head insert with trigger side effects', async () => {
    const env = await makeEnv();
    await createLocalSpace(env, firstSpace);
    await env.ALTERAN_DB.prepare(
      `CREATE TRIGGER ignore_new_head BEFORE INSERT ON space_repo
       BEGIN UPDATE space SET deleted_at = 1 WHERE space_ref = NEW.space_ref; SELECT RAISE(IGNORE); END`,
    ).run();
    await expect(applySpaceWrites(env, firstSpace, did, [create(collection, 'a', 'private')])).rejects.toThrow();
    expect((await env.ALTERAN_DB.prepare('SELECT deleted_at FROM space WHERE space_ref = ?').bind(firstSpace).first())?.deleted_at)
      .toBeNull();
    for (const table of ['space_repo', 'space_epoch', 'space_record', 'space_record_version', 'space_op', 'space_commit_assertion']) {
      expect((await env.ALTERAN_DB.prepare(`SELECT COUNT(*) AS count FROM ${table}`).first())?.count).toBe(0);
    }
  });

  it('rolls back an updated head whose winning nonce is changed by a trigger', async () => {
    const env = await makeEnv();
    await createLocalSpace(env, firstSpace);
    const first = await applySpaceWrites(env, firstSpace, did, [create(collection, 'a', 'old')]);
    await env.ALTERAN_DB.prepare(
      `CREATE TRIGGER disturb_updated_head AFTER UPDATE ON space_repo
       WHEN NEW.generation = 2 AND NEW.mutation_id != 'changed'
       BEGIN UPDATE space_repo SET mutation_id = 'changed' WHERE space_ref = NEW.space_ref AND repo_did = NEW.repo_did; END`,
    ).run();
    await expect(applySpaceWrites(env, firstSpace, did, [update(collection, 'a', 'new')])).rejects.toThrow();
    const head = await env.ALTERAN_DB.prepare('SELECT generation, rev, set_hash FROM space_repo WHERE space_ref = ? AND repo_did = ?')
      .bind(firstSpace, did).first<{ generation: number; rev: string; set_hash: number[] }>();
    expect(head?.generation).toBe(first!.generation);
    expect(head?.rev).toBe(first!.rev);
    expect(Uint8Array.from(head!.set_hash)).toEqual(first!.setHash);
    expect(dagCbor.decode((await getSpaceRecord(env, firstSpace, did, collection, 'a'))!.value)).toMatchObject({ text: 'old' });
    expect((await env.ALTERAN_DB.prepare('SELECT COUNT(*) AS count FROM space_commit_assertion').first())?.count).toBe(0);
    await env.ALTERAN_DB.prepare('DROP TRIGGER disturb_updated_head').run();
    const updated = await applySpaceWrites(env, firstSpace, did, [update(collection, 'a', 'new')]);
    const current = await getSpaceRecord(env, firstSpace, did, collection, 'a');
    const expected = applySpaceSetHashChanges(null, [{ action: 'add', element: spaceRecordHashElement(collection, 'a', current!.cid) }]);
    expect(updated!.data).toEqual(spaceSetHashDigest(expected));
  });

  it('rolls back a silently ignored head update with trigger side effects', async () => {
    const env = await makeEnv();
    await createLocalSpace(env, firstSpace);
    const first = await applySpaceWrites(env, firstSpace, did, [create(collection, 'a', 'old')]);
    await env.ALTERAN_DB.prepare(
      `CREATE TRIGGER ignore_updated_head BEFORE UPDATE ON space_repo WHEN NEW.generation = 2
       BEGIN UPDATE space_repo SET set_hash = zeroblob(2048) WHERE space_ref = NEW.space_ref AND repo_did = NEW.repo_did;
         SELECT RAISE(IGNORE); END`,
    ).run();
    await expect(applySpaceWrites(env, firstSpace, did, [update(collection, 'a', 'new')])).rejects.toThrow();
    const head = await env.ALTERAN_DB.prepare('SELECT generation, rev, set_hash FROM space_repo WHERE space_ref = ? AND repo_did = ?')
      .bind(firstSpace, did).first<{ generation: number; rev: string; set_hash: number[] }>();
    expect(head?.generation).toBe(first!.generation);
    expect(head?.rev).toBe(first!.rev);
    expect(Uint8Array.from(head!.set_hash)).toEqual(first!.setHash);
    expect(dagCbor.decode((await getSpaceRecord(env, firstSpace, did, collection, 'a'))!.value)).toMatchObject({ text: 'old' });
  });

  it('rolls back if an effect trigger changes the head after the initial check', async () => {
    const env = await makeEnv();
    await createLocalSpace(env, firstSpace);
    const first = await applySpaceWrites(env, firstSpace, did, [create(collection, 'a', 'old')]);
    await env.ALTERAN_DB.prepare(
      `CREATE TRIGGER disturb_head_after_close AFTER UPDATE OF until_generation ON space_record_version
       BEGIN UPDATE space_repo SET mutation_id = 'changed' WHERE space_ref = NEW.space_ref AND repo_did = NEW.repo_did; END`,
    ).run();
    await expect(applySpaceWrites(env, firstSpace, did, [update(collection, 'a', 'new')])).rejects.toThrow();
    expect(await env.ALTERAN_DB.prepare('SELECT generation, rev FROM space_repo WHERE space_ref = ? AND repo_did = ?')
      .bind(firstSpace, did).first()).toEqual({ generation: first!.generation, rev: first!.rev });
    expect(dagCbor.decode((await getSpaceRecord(env, firstSpace, did, collection, 'a'))!.value)).toMatchObject({ text: 'old' });
    const versions = await env.ALTERAN_DB.prepare('SELECT from_generation, until_generation FROM space_record_version WHERE space_ref = ?')
      .bind(firstSpace).all();
    expect(versions.results).toEqual([{ from_generation: 1, until_generation: null }]);
  });

  it('rolls back if a trigger changes the hash while retaining the winning nonce', async () => {
    const env = await makeEnv();
    await createLocalSpace(env, firstSpace);
    const first = await applySpaceWrites(env, firstSpace, did, [create(collection, 'a', 'old')]);
    await env.ALTERAN_DB.prepare(
      `CREATE TRIGGER corrupt_head_hash AFTER UPDATE ON space_repo
       WHEN NEW.generation = 2 AND NEW.set_hash != zeroblob(2048)
       BEGIN UPDATE space_repo SET set_hash = zeroblob(2048)
         WHERE space_ref = NEW.space_ref AND repo_did = NEW.repo_did; END`,
    ).run();
    await expect(applySpaceWrites(env, firstSpace, did, [update(collection, 'a', 'new')])).rejects.toThrow();
    const head = await env.ALTERAN_DB.prepare('SELECT generation, rev, set_hash FROM space_repo WHERE space_ref = ? AND repo_did = ?')
      .bind(firstSpace, did).first<{ generation: number; rev: string; set_hash: number[] }>();
    expect(head?.generation).toBe(first!.generation);
    expect(head?.rev).toBe(first!.rev);
    expect(Uint8Array.from(head!.set_hash)).toEqual(first!.setHash);
    expect(dagCbor.decode((await getSpaceRecord(env, firstSpace, did, collection, 'a'))!.value)).toMatchObject({ text: 'old' });
  });

  it('rolls back when the winning marker insert is silently skipped', async () => {
    const env = await makeEnv();
    await createLocalSpace(env, firstSpace);
    const first = await applySpaceWrites(env, firstSpace, did, [create(collection, 'a', 'old')]);
    await env.ALTERAN_DB.prepare(
      `CREATE TRIGGER skip_commit_marker BEFORE INSERT ON space_commit_assertion BEGIN SELECT RAISE(IGNORE); END`,
    ).run();
    await expect(applySpaceWrites(env, firstSpace, did, [update(collection, 'a', 'new')])).rejects.toThrow();
    expect(await env.ALTERAN_DB.prepare('SELECT generation, rev FROM space_repo WHERE space_ref = ? AND repo_did = ?')
      .bind(firstSpace, did).first()).toEqual({ generation: first!.generation, rev: first!.rev });
    expect(dagCbor.decode((await getSpaceRecord(env, firstSpace, did, collection, 'a'))!.value)).toMatchObject({ text: 'old' });
  });

  it('rolls back when the winning marker cleanup is silently skipped', async () => {
    const env = await makeEnv();
    await createLocalSpace(env, firstSpace);
    const first = await applySpaceWrites(env, firstSpace, did, [create(collection, 'a', 'old')]);
    await env.ALTERAN_DB.prepare(
      `CREATE TRIGGER skip_commit_cleanup BEFORE DELETE ON space_commit_assertion BEGIN SELECT RAISE(IGNORE); END`,
    ).run();
    await expect(applySpaceWrites(env, firstSpace, did, [update(collection, 'a', 'new')])).rejects.toThrow();
    expect(await env.ALTERAN_DB.prepare('SELECT generation, rev FROM space_repo WHERE space_ref = ? AND repo_did = ?')
      .bind(firstSpace, did).first()).toEqual({ generation: first!.generation, rev: first!.rev });
    expect(dagCbor.decode((await getSpaceRecord(env, firstSpace, did, collection, 'a'))!.value)).toMatchObject({ text: 'old' });
    expect((await env.ALTERAN_DB.prepare('SELECT COUNT(*) AS count FROM space_commit_assertion').first())?.count).toBe(0);
  });

  it('recognizes a winning root even when a trigger makes D1 count extra changes', async () => {
    const env = await makeEnv();
    await createLocalSpace(env, firstSpace);
    await applySpaceWrites(env, firstSpace, did, [create(collection, 'a', 'old')]);
    await env.ALTERAN_DB.prepare('CREATE TABLE space_test_audit (value INTEGER)').run();
    await env.ALTERAN_DB.prepare(
      `CREATE TRIGGER audit_head AFTER UPDATE ON space_repo BEGIN INSERT INTO space_test_audit (value) VALUES (1); END`,
    ).run();
    const result = await applySpaceWrites(env, firstSpace, did, [update(collection, 'a', 'new')]);
    expect(result!.generation).toBe(2);
    expect((await env.ALTERAN_DB.prepare('SELECT COUNT(*) AS count FROM space_test_audit').first())?.count).toBe(1);
    expect(dagCbor.decode((await getSpaceRecord(env, firstSpace, did, collection, 'a'))!.value)).toMatchObject({ text: 'new' });
  });

});
