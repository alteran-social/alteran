import { describe, it } from './helpers/bdd';
import { expect } from '@std/expect';
import { makeEnv } from './helpers/env';
import { createLocalSpace, applySpaceWrites, getSpaceRecord } from '../src/db/space-store';
import { acquireSpaceSnapshot, readSpaceSnapshotPage } from '../src/db/space-snapshot';
import { createPersonalSpace } from '../src/db/space-lifecycle-create';
import { beginPersonalSpaceDeletion, getPersonalSpaceDeletion } from '../src/db/space-lifecycle-delete';
import { stepPersonalSpaceDeletion } from '../src/db/space-lifecycle-cleanup';
import { assertCleanupCandidates, CLEANUP_PHASES, insertCleanupCandidates } from '../src/db/space-lifecycle-cleanup-sql';
import { streamSpaceRepoArchive } from '../src/services/space-repo-export';
import type { PersonalDeletionHandle } from '../src/db/space-lifecycle-types';

const DID = 'did:example:test';
const SPACE = `at://${DID}/space/com.example.notes/lifecycle`;
const COLLECTION = 'com.example.note';
const POLICY = { $type: 'com.atproto.personalspace.policy' };
type TestEnv = Awaited<ReturnType<typeof makeEnv>>;
function create(rkey: string, text = 'same') {
  return { action: 'create' as const, collection: COLLECTION, rkey, record: { $type: COLLECTION, text } };
}
async function fixture(keys: string[] = ['a', 'b', 'c']) {
  const env = await makeEnv();
  await createPersonalSpace(env, SPACE, POLICY, crypto.randomUUID());
  if (keys.length) await applySpaceWrites(env, SPACE, DID, keys.map((key) => create(key)));
  return env;
}
async function begin(env: TestEnv): Promise<PersonalDeletionHandle> {
  const result = await beginPersonalSpaceDeletion(env, SPACE, crypto.randomUUID());
  if (result.tag !== 'started') throw new Error(`Could not start deletion: ${result.tag}`);
  return result.handle;
}
async function count(env: TestEnv, table: string): Promise<number> {
  return (await env.ALTERAN_DB.prepare(`SELECT COUNT(*) AS count FROM ${table}`).first<{count: number}>())!.count;
}
function lostBatch(env: TestEnv, batchLength: number): TestEnv {
  let lost = false;
  const database = env.ALTERAN_DB;
  return { ...env, ALTERAN_DB: new Proxy(database, { get(target, key) {
    if (key === 'batch') return async (statements: Parameters<typeof database.batch>[0]) => {
      const result = await database.batch(statements);
      if (!lost && statements.length === batchLength) { lost = true; throw new Error('Lost committed response'); }
      return result;
    };
    const value = Reflect.get(target, key, target);
    return typeof value === 'function' ? value.bind(target) : value;
  } }) };
}
async function rejected(action: () => Promise<unknown>) {
  let failed = false;
  try { await action(); } catch { failed = true; }
  expect(failed).toBe(true);
}

describe('internal personal Space lifecycle', () => {
  it('creates an immutable explicit policy, recovers lost responses and leaves legacy Spaces unclassified', async () => {
    const env = await makeEnv(), nonce = crypto.randomUUID();
    await createPersonalSpace(lostBatch(env, 6), SPACE, POLICY, nonce);
    await createPersonalSpace(env, SPACE, POLICY, nonce);
    expect(await count(env, 'space_personal_policy')).toBe(1);
    expect(await count(env, 'space_personal_creation_attempt')).toBe(0);
    await rejected(() => createPersonalSpace(env, SPACE, POLICY, crypto.randomUUID()));
    await rejected(() => createPersonalSpace(env, `${SPACE}x`, { $type: 'com.atproto.memberspace.policy' }, crypto.randomUUID()));
    await rejected(() => env.ALTERAN_DB.prepare('UPDATE space_personal_policy SET notification_state = ?').bind('changed').run());
    await rejected(() => env.ALTERAN_DB.prepare('INSERT OR REPLACE INTO space SELECT * FROM space WHERE space_ref = ?').bind(SPACE).run());
    const legacy = `${SPACE}legacy`;
    await createLocalSpace(env, legacy);
    expect((await beginPersonalSpaceDeletion(env, legacy, crypto.randomUUID())).tag).toBe('unsupported');
    expect((await env.ALTERAN_DB.prepare('DELETE FROM space WHERE space_ref = ?').bind(legacy).run()).meta.changes).toBe(1);
  });
  it('revokes old leases and writers atomically, retains a tombstone and recovers the deletion receipt', async () => {
    const env = await fixture(['a']), lease = await acquireSpaceSnapshot(env, SPACE, DID), nonce = crypto.randomUUID();
    expect((await beginPersonalSpaceDeletion(lostBatch(env, 5), SPACE, nonce)).tag).toBe('started');
    expect((await beginPersonalSpaceDeletion(env, SPACE, nonce)).tag).toBe('started');
    expect((await beginPersonalSpaceDeletion(env, SPACE, crypto.randomUUID())).tag).toBe('unsupported');
    expect(await count(env, 'space_snapshot_lease')).toBe(0);
    expect(await getSpaceRecord(env, SPACE, DID, COLLECTION, 'a')).toBeNull();
    await rejected(() => readSpaceSnapshotPage(env, lease, null));
    await rejected(() => acquireSpaceSnapshot(env, SPACE, DID));
    await rejected(() => applySpaceWrites(env, SPACE, DID, [create('b')]));
    await rejected(() => env.ALTERAN_DB.prepare(`INSERT INTO space_mutation_attempt
      SELECT ?, space_ref, repo_did, active_epoch_id, generation, rev, set_hash FROM space_repo WHERE space_ref = ?`)
      .bind(crypto.randomUUID(), SPACE).run());
    await rejected(() => env.ALTERAN_DB.prepare(`INSERT INTO space_snapshot_lease
      (id, token, renewal_nonce, space_ref, repo_did, epoch_id, generation, rev, set_hash, expires_at, maximum_expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, unixepoch() + 60, unixepoch() + 900)`)
      .bind(crypto.randomUUID(), lease.token, crypto.randomUUID(), SPACE, DID, lease.epochId,
        lease.generation, lease.rev, lease.setHash.buffer).run());
    await rejected(() => env.ALTERAN_DB.prepare("UPDATE space_epoch SET state = 'active' WHERE id = ?").bind(lease.epochId).run());
    await rejected(() => env.ALTERAN_DB.prepare('DELETE FROM space WHERE space_ref = ?').bind(SPACE).run());
    await rejected(() => env.ALTERAN_DB.prepare('INSERT OR REPLACE INTO space SELECT * FROM space WHERE space_ref = ?').bind(SPACE).run());
    await rejected(() => createPersonalSpace(env, SPACE, POLICY, crypto.randomUUID()));
  });
  it('rolls back skipped epoch or lease deletion and rejects blob associations', async () => {
    const env = await fixture(['a']), lease = await acquireSpaceSnapshot(env, SPACE, DID);
    await env.ALTERAN_DB.exec("CREATE TRIGGER skip_deleting_epoch BEFORE UPDATE OF state ON space_epoch WHEN NEW.state = 'deleting' BEGIN SELECT RAISE(IGNORE); END");
    expect((await beginPersonalSpaceDeletion(env, SPACE, crypto.randomUUID())).tag).toBe('unavailable');
    expect(await count(env, 'space_personal_deletion_job')).toBe(0);
    expect(await count(env, 'space_snapshot_lease')).toBe(1);
    expect((await readSpaceSnapshotPage(env, lease, null)).records).toHaveLength(1);
    await env.ALTERAN_DB.exec('DROP TRIGGER skip_deleting_epoch');
    await env.ALTERAN_DB.exec('CREATE TRIGGER skip_lease_delete BEFORE DELETE ON space_snapshot_lease BEGIN SELECT RAISE(IGNORE); END');
    expect((await beginPersonalSpaceDeletion(env, SPACE, crypto.randomUUID())).tag).toBe('unavailable');
    expect(await count(env, 'space_personal_deletion_job')).toBe(0);
    await env.ALTERAN_DB.exec('DROP TRIGGER skip_lease_delete');
    await env.ALTERAN_DB.exec('DROP TRIGGER space_blob_usage_fence_insert');
    await env.ALTERAN_DB.prepare('INSERT INTO space_blob_usage VALUES (?, ?, ?, ?, ?, ?)').bind(SPACE, DID, COLLECTION, 'a', 'cid', 'key').run();
    expect((await beginPersonalSpaceDeletion(env, SPACE, crypto.randomUUID())).tag).toBe('unsupported');
    expect(await count(env, 'space_personal_deletion_job')).toBe(0);
  });
  it('fences a writer that captured its snapshot before the tombstone', async () => {
    const env = await fixture(['a']);
    let resume!: () => void, paused!: () => void;
    const wait = new Promise<void>((resolve) => resume = resolve), ready = new Promise<void>((resolve) => paused = resolve);
    let blocked = false;
    const database = env.ALTERAN_DB;
    const watched = { ...env, ALTERAN_DB: new Proxy(database, { get(target, key) {
      if (key === 'batch') return async (statements: Parameters<typeof database.batch>[0]) => {
        const result = await database.batch(statements);
        if (!blocked && statements.length === 3) { blocked = true; paused(); await wait; }
        return result;
      };
      const value = Reflect.get(target, key, target); return typeof value === 'function' ? value.bind(target) : value;
    } }) };
    const write = applySpaceWrites(watched, SPACE, DID, [create('late')]).then(() => false, () => true);
    await ready;
    await begin(env);
    resume();
    expect(await write).toBe(true);
    expect(await count(env, 'space_record')).toBe(1);
    expect(await count(env, 'space_op')).toBe(1);
  });
  it('serializes concurrent deletion jobs and only the winning nonce reads the receipt', async () => {
    const env = await fixture(['a']), first = crypto.randomUUID(), second = crypto.randomUUID();
    const results = await Promise.all([beginPersonalSpaceDeletion(env, SPACE, first), beginPersonalSpaceDeletion(env, SPACE, second)]);
    expect(results.filter((result) => result.tag === 'started')).toHaveLength(1);
    expect(await count(env, 'space_personal_deletion_job')).toBe(1);
    const winner = results.find((result) => result.tag === 'started');
    if (!winner || winner.tag !== 'started') throw new Error('Missing deletion winner');
    expect(await getPersonalSpaceDeletion(env, { ...winner.handle, nonce: winner.handle.nonce === first ? second : first })).toBeNull();
  });
  it('rechecks late hash-copy insertion and rolls the whole tombstone transaction back', async () => {
    const env = await fixture(['a']);
    await env.ALTERAN_DB.exec(`CREATE TRIGGER late_mutation AFTER INSERT ON space_personal_deletion_job BEGIN
      INSERT INTO space_mutation_attempt SELECT 'late', space_ref, repo_did, active_epoch_id, generation, rev, set_hash
      FROM space_repo WHERE space_ref = NEW.space_ref; END`.replace(/\n/g, ' '));
    expect((await beginPersonalSpaceDeletion(env, SPACE, crypto.randomUUID())).tag).toBe('unavailable');
    expect(await count(env, 'space_mutation_attempt')).toBe(0);
    expect(await count(env, 'space_personal_deletion_job')).toBe(0);
    expect(await getSpaceRecord(env, SPACE, DID, COLLECTION, 'a')).not.toBeNull();
  });
  it('fails closed on excess or malformed leases and revokes exactly sixteen valid leases', async () => {
    const env = await fixture(['a']);
    await acquireSpaceSnapshot(env, SPACE, DID);
    for (let i = 0; i < 15; i++) {
      await env.ALTERAN_DB.prepare(`INSERT INTO space_snapshot_lease
        SELECT ?, token, renewal_nonce, space_ref, repo_did, epoch_id, generation, rev, set_hash, expires_at, maximum_expires_at
        FROM space_snapshot_lease LIMIT 1`).bind(crypto.randomUUID()).run();
    }
    await env.ALTERAN_DB.exec('DROP TRIGGER space_snapshot_lease_quota');
    const extra = crypto.randomUUID();
    await env.ALTERAN_DB.prepare(`INSERT INTO space_snapshot_lease
      SELECT ?, token, renewal_nonce, space_ref, repo_did, epoch_id, generation, rev, set_hash, expires_at, maximum_expires_at
      FROM space_snapshot_lease LIMIT 1`).bind(extra).run();
    expect((await beginPersonalSpaceDeletion(env, SPACE, crypto.randomUUID())).tag).toBe('unavailable');
    expect(await count(env, 'space_snapshot_lease')).toBe(17);
    await env.ALTERAN_DB.prepare('DELETE FROM space_snapshot_lease WHERE id = ?').bind(extra).run();
    await env.ALTERAN_DB.exec('DROP TRIGGER space_snapshot_lease_identity_immutable');
    const lease = await env.ALTERAN_DB.prepare('SELECT id, rev FROM space_snapshot_lease LIMIT 1').first<{id: string; rev: string}>();
    await env.ALTERAN_DB.prepare('UPDATE space_snapshot_lease SET rev = ? WHERE id = ?').bind(`\0${'x'.repeat(400_000)}`, lease!.id).run();
    expect((await beginPersonalSpaceDeletion(env, SPACE, crypto.randomUUID())).tag).toBe('unavailable');
    await env.ALTERAN_DB.prepare('UPDATE space_snapshot_lease SET rev = ? WHERE id = ?').bind(lease!.rev, lease!.id).run();
    expect((await beginPersonalSpaceDeletion(env, SPACE, crypto.randomUUID())).tag).toBe('started');
    expect(await count(env, 'space_snapshot_lease')).toBe(0);
  });
  it('cleans records, versions and operations in resumable pages with retry receipts', async () => {
    const env = await fixture(['a', 'b', 'c', 'd', 'e']);
    await applySpaceWrites(env, SPACE, DID, ['a', 'b'].map((rkey) => ({ action: 'update' as const, collection: COLLECTION, rkey, record: { $type: COLLECTION, text: 'new' } })));
    const handle = await begin(env), nonce = crypto.randomUUID();
    const first = await stepPersonalSpaceDeletion(lostBatch(env, 14), handle, 0, nonce, 2);
    expect(first.tag).toBe('progress');
    expect(await stepPersonalSpaceDeletion(env, handle, 0, nonce, 2)).toEqual(first);
    expect((await stepPersonalSpaceDeletion(env, handle, 0, crypto.randomUUID(), 2)).tag).toBe('conflict');
    let sequence = 1;
    for (; sequence < 30; sequence++) {
      const next = await stepPersonalSpaceDeletion(env, handle, sequence, crypto.randomUUID(), 2);
      expect(['progress', 'complete']).toContain(next.tag);
      if (next.tag === 'progress' || next.tag === 'complete') expect(next.status.lastStepCount).toBeLessThanOrEqual(2);
      if (next.tag === 'complete') break;
    }
    expect(sequence).toBeLessThan(30);
    for (const table of ['space_record', 'space_record_version', 'space_op', 'space_personal_deletion_attempt', 'space_personal_deletion_candidate']) expect(await count(env, table)).toBe(0);
    for (const table of ['space', 'space_epoch', 'space_personal_policy']) expect(await count(env, table)).toBe(1);
    expect((await getPersonalSpaceDeletion(env, handle))?.status).toBe('complete');
    const head = await env.ALTERAN_DB.prepare('SELECT rev, generation, mutation_id, set_hash = zeroblob(2048) AS neutral FROM space_repo WHERE space_ref = ?').bind(SPACE).first();
    expect(head).toEqual({ rev: null, generation: 0, mutation_id: handle.nonce, neutral: 1 });
  });
  it('resolves concurrent cleanup attempts by sequence and nonce', async () => {
    const env = await fixture(['a', 'b', 'c']), handle = await begin(env);
    const results = await Promise.all([stepPersonalSpaceDeletion(env, handle, 0, crypto.randomUUID(), 1), stepPersonalSpaceDeletion(env, handle, 0, crypto.randomUUID(), 1)]);
    expect(results.filter((result) => result.tag === 'progress')).toHaveLength(1);
    expect(results.filter((result) => result.tag === 'conflict')).toHaveLength(1);
    expect(await count(env, 'space_record')).toBe(2);
    const nonce = crypto.randomUUID();
    const same = await Promise.all([stepPersonalSpaceDeletion(env, handle, 1, nonce, 1), stepPersonalSpaceDeletion(env, handle, 1, nonce, 1)]);
    expect(same[0]).toEqual(same[1]);
    expect(same[0].tag).toBe('progress');
    expect(await count(env, 'space_record')).toBe(1);
  });
  it('rolls back skipped or extra target deletion and rejects same-size candidate substitution', async () => {
    const env = await fixture(['a', 'b', 'c']), handle = await begin(env);
    await env.ALTERAN_DB.exec('CREATE TRIGGER skip_candidate BEFORE INSERT ON space_personal_deletion_candidate BEGIN SELECT RAISE(IGNORE); END');
    expect((await stepPersonalSpaceDeletion(env, handle, 0, crypto.randomUUID(), 1)).tag).toBe('unavailable');
    await env.ALTERAN_DB.exec('DROP TRIGGER skip_candidate');
    await env.ALTERAN_DB.exec(`CREATE TRIGGER add_candidate AFTER INSERT ON space_personal_deletion_candidate BEGIN
      INSERT INTO space_personal_deletion_candidate SELECT NEW.attempt_nonce, rowid, length(value_cbor)
      FROM space_record WHERE rowid != NEW.row_id LIMIT 1; END`.replace(/\n/g, ' '));
    expect((await stepPersonalSpaceDeletion(env, handle, 0, crypto.randomUUID(), 1)).tag).toBe('unavailable');
    await env.ALTERAN_DB.exec('DROP TRIGGER add_candidate');
    await env.ALTERAN_DB.exec('CREATE TRIGGER skip_record BEFORE DELETE ON space_record BEGIN SELECT RAISE(IGNORE); END');
    expect((await stepPersonalSpaceDeletion(env, handle, 0, crypto.randomUUID(), 1)).tag).toBe('unavailable');
    await env.ALTERAN_DB.exec('DROP TRIGGER skip_record');
    await env.ALTERAN_DB.exec('CREATE TRIGGER delete_extra BEFORE DELETE ON space_record BEGIN DELETE FROM space_record WHERE rowid = (SELECT MAX(rowid) FROM space_record) AND rowid != OLD.rowid; END');
    expect((await stepPersonalSpaceDeletion(env, handle, 0, crypto.randomUUID(), 1)).tag).toBe('unavailable');
    await env.ALTERAN_DB.exec('DROP TRIGGER delete_extra');
    await env.ALTERAN_DB.exec('CREATE TRIGGER skip_attempt_cleanup BEFORE DELETE ON space_personal_deletion_attempt BEGIN SELECT RAISE(IGNORE); END');
    expect((await stepPersonalSpaceDeletion(env, handle, 0, crypto.randomUUID(), 1)).tag).toBe('unavailable');
    await env.ALTERAN_DB.exec('DROP TRIGGER skip_attempt_cleanup');
    expect(await count(env, 'space_record')).toBe(3);
    expect((await getPersonalSpaceDeletion(env, handle))?.sequence).toBe(0);
    expect(await count(env, 'space_personal_deletion_candidate')).toBe(0);
    expect(await count(env, 'space_personal_deletion_attempt')).toBe(0);
    const step = crypto.randomUUID();
    const attempt = env.ALTERAN_DB.prepare(`INSERT INTO space_personal_deletion_attempt SELECT ?, nonce, space_ref, authority_did, epoch_id, phase, sequence, 'building', 1, 0, 0 FROM space_personal_deletion_job WHERE nonce = ?`).bind(step, handle.nonce);
    const substitute = env.ALTERAN_DB.prepare('INSERT INTO space_personal_deletion_candidate SELECT ?, rowid, length(value_cbor) FROM space_record WHERE space_ref = ? AND repo_did = ? ORDER BY collection, rkey DESC LIMIT 1').bind(step, SPACE, DID);
    const assertion = env.ALTERAN_DB.prepare(assertCleanupCandidates(CLEANUP_PHASES.records.scan)).bind(SPACE, DID, 1, step, step, step);
    await rejected(() => env.ALTERAN_DB.batch([attempt, substitute, assertion]));
    expect(await count(env, 'space_personal_deletion_attempt')).toBe(0);
  });
  it('rejects oversized corrupted job metadata before it crosses D1', async () => {
    const env = await fixture(['a']), handle = await begin(env);
    await env.ALTERAN_DB.exec('DROP TRIGGER space_personal_deletion_job_update');
    await env.ALTERAN_DB.prepare('UPDATE space_personal_deletion_job SET last_step_phase = ? WHERE nonce = ?').bind(`\0${'x'.repeat(400_000)}`, handle.nonce).run();
    let largest = 0;
    const database = env.ALTERAN_DB;
    const watched = { ...env, ALTERAN_DB: new Proxy(database, { get(target, key) {
      if (key === 'prepare') return (sql: string) => new Proxy(target.prepare(sql), { get(statement, member) {
        if (member === 'bind') return (...values: unknown[]) => new Proxy(statement.bind(...values), { get(query, operation) {
          if (operation === 'first') return async () => { const result = await query.first(); largest = Math.max(largest, JSON.stringify(result)?.length ?? 0); return result; };
          const value = Reflect.get(query, operation, query); return typeof value === 'function' ? value.bind(query) : value;
        } });
        const value = Reflect.get(statement, member, statement); return typeof value === 'function' ? value.bind(statement) : value;
      } });
      const value = Reflect.get(target, key, target); return typeof value === 'function' ? value.bind(target) : value;
    } }) };
    expect(await getPersonalSpaceDeletion(watched, handle)).toBeNull();
    expect(largest).toBeLessThan(1000);
  });
  it('enforces a 4 MiB byte budget and deployed D1 bind and value limits', async () => {
    const env = await fixture([]);
    for (let i = 0; i < 6; i++) await applySpaceWrites(env, SPACE, DID, [create(`large-${i}`, 'x'.repeat(900_000))]);
    const largestRow = await env.ALTERAN_DB.prepare(`SELECT MAX(length(value_cbor) + length(CAST(space_ref AS BLOB)) +
      length(CAST(repo_did AS BLOB)) + length(CAST(collection AS BLOB)) + length(CAST(rkey AS BLOB)) +
      length(CAST(cid AS BLOB)) + length(CAST(repo_rev AS BLOB))) AS bytes FROM space_record`).first<{bytes: number}>();
    expect(largestRow!.bytes).toBeLessThan(2_000_000);
    const handle = await begin(env);
    let maxBinds = 0, maxValue = 0, maxTransfer = 0;
    const encoder = new TextEncoder(), database = env.ALTERAN_DB;
    const watched = { ...env, ALTERAN_DB: new Proxy(database, { get(target, key) {
      if (key === 'batch') return async (statements: Parameters<typeof database.batch>[0]) => {
        const result = await database.batch(statements); maxTransfer = Math.max(maxTransfer, JSON.stringify(result).length); return result;
      };
      if (key === 'prepare') return (sql: string) => new Proxy(target.prepare(sql), { get(statement, member) {
        if (member === 'bind') return (...values: unknown[]) => {
          maxBinds = Math.max(maxBinds, values.length);
          for (const value of values) {
            if (typeof value === 'string') maxValue = Math.max(maxValue, encoder.encode(value).byteLength);
            else if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) maxValue = Math.max(maxValue, value.byteLength);
          }
          return statement.bind(...values);
        };
        const value = Reflect.get(statement, member, statement); return typeof value === 'function' ? value.bind(statement) : value;
      } });
      const value = Reflect.get(target, key, target); return typeof value === 'function' ? value.bind(target) : value;
    } }) };
    const result = await stepPersonalSpaceDeletion(watched, handle, 0, crypto.randomUUID(), 32);
    expect(result.tag).toBe('progress');
    if (result.tag === 'progress') expect(result.status.lastStepCount).toBe(4);
    expect(await count(env, 'space_record')).toBe(2);
    for (let sequence = 1; sequence < 12; sequence++) {
      const step = await stepPersonalSpaceDeletion(watched, handle, sequence, crypto.randomUUID(), 32);
      expect(['progress', 'complete']).toContain(step.tag);
      if (step.tag === 'complete') break;
      expect(sequence).toBeLessThan(11);
    }
    expect(maxBinds).toBeLessThanOrEqual(100);
    expect(maxValue).toBeLessThan(2_000_000);
    expect(maxTransfer).toBeLessThan(100_000);
  });
  it('deletes a full 32-row page and rejects malformed record values without progress', async () => {
    const env = await fixture(Array.from({ length: 32 }, (_, i) => `row-${String(i).padStart(2, '0')}`));
    const handle = await begin(env);
    const first = await stepPersonalSpaceDeletion(env, handle, 0, crypto.randomUUID(), 32);
    expect(first.tag).toBe('progress');
    if (first.tag === 'progress') expect(first.status.lastStepCount).toBe(32);
    expect(await count(env, 'space_record')).toBe(0);
    const corrupt = await fixture(['a']), badHandle = await begin(corrupt);
    await corrupt.ALTERAN_DB.exec('DROP TRIGGER space_record_fence_update');
    await corrupt.ALTERAN_DB.prepare('UPDATE space_record SET value_cbor = ? WHERE space_ref = ?').bind(`\0${'x'.repeat(400_000)}`, SPACE).run();
    expect((await stepPersonalSpaceDeletion(corrupt, badHandle, 0, crypto.randomUUID())).tag).toBe('unavailable');
    expect((await getPersonalSpaceDeletion(corrupt, badHandle))?.sequence).toBe(0);
    expect(await count(corrupt, 'space_record')).toBe(1);
  });
  it('seeks a bounded candidate page before sorting and deletes by rowid', async () => {
    const env = await fixture(['a']);
    for (const phase of ['records', 'versions', 'ops'] as const) {
      const sql = CLEANUP_PHASES[phase];
      const scan = phase === 'versions' ? [crypto.randomUUID(), 32] : [SPACE, DID, 32];
      const selected = await env.ALTERAN_DB.prepare(`EXPLAIN QUERY PLAN ${insertCleanupCandidates(sql.scan)}`).bind(...scan, crypto.randomUUID()).all<{detail: string}>();
      const plan = selected.results.map((row: { detail: string }) => row.detail).join('\n');
      expect(plan).toContain('MATERIALIZE candidates');
      expect(plan).toContain(phase === 'records' ? 'sqlite_autoindex_space_record_1' : phase === 'versions' ? 'sqlite_autoindex_space_record_version_1' : 'sqlite_autoindex_space_op_1');
      const args = phase === 'versions' ? [crypto.randomUUID(), SPACE, DID, crypto.randomUUID()] : [crypto.randomUUID(), SPACE, DID];
      const deleted = await env.ALTERAN_DB.prepare(`EXPLAIN QUERY PLAN ${sql.remove}`).bind(...args).all<{detail: string}>();
      expect(deleted.results.map((row: { detail: string }) => row.detail).join('\n')).toContain('INTEGER PRIMARY KEY (rowid=?)');
    }
    for (const [table, index] of [['space_mutation_attempt', 'space_mutation_attempt_owner'], ['space_quarantine_job', 'space_quarantine_job_owner_epoch']]) {
      const plan = await env.ALTERAN_DB.prepare(`EXPLAIN QUERY PLAN SELECT 1 FROM ${table} WHERE space_ref = ? LIMIT 1`).bind(SPACE).all<{detail: string}>();
      expect(plan.results.map((row: { detail: string }) => row.detail).join('\n')).toContain(index);
    }
  });
  it('rolls back skipped or rewritten final head scrubs and recovers a lost terminal response', async () => {
    const env = await fixture(['a']), handle = await begin(env);
    expect((await stepPersonalSpaceDeletion(env, handle, 0, crypto.randomUUID())).tag).toBe('progress');
    expect((await stepPersonalSpaceDeletion(env, handle, 1, crypto.randomUUID())).tag).toBe('progress');
    const before = await env.ALTERAN_DB.prepare('SELECT rev, generation, mutation_id, hex(set_hash) AS hash FROM space_repo WHERE space_ref = ?').bind(SPACE).first();
    await env.ALTERAN_DB.exec("CREATE TRIGGER skip_scrub BEFORE UPDATE ON space_repo WHEN NEW.generation = 0 BEGIN SELECT RAISE(IGNORE); END");
    expect((await stepPersonalSpaceDeletion(env, handle, 2, crypto.randomUUID())).tag).toBe('unavailable');
    expect(await count(env, 'space_op')).toBe(1);
    expect((await getPersonalSpaceDeletion(env, handle))?.sequence).toBe(2);
    expect(await env.ALTERAN_DB.prepare('SELECT rev, generation, mutation_id, hex(set_hash) AS hash FROM space_repo WHERE space_ref = ?').bind(SPACE).first()).toEqual(before);
    await env.ALTERAN_DB.exec('DROP TRIGGER skip_scrub');
    await env.ALTERAN_DB.exec("CREATE TRIGGER rewrite_scrub AFTER UPDATE ON space_repo WHEN NEW.generation = 0 BEGIN UPDATE space_repo SET rev = 'forged' WHERE space_ref = NEW.space_ref; END");
    expect((await stepPersonalSpaceDeletion(env, handle, 2, crypto.randomUUID())).tag).toBe('unavailable');
    await env.ALTERAN_DB.exec('DROP TRIGGER rewrite_scrub');
    const nonce = crypto.randomUUID();
    const completed = await stepPersonalSpaceDeletion(lostBatch(env, 16), handle, 2, nonce);
    expect(completed.tag).toBe('complete');
    expect(await stepPersonalSpaceDeletion(env, handle, 2, nonce)).toEqual(completed);
    expect((await env.ALTERAN_DB.prepare('SELECT set_hash = zeroblob(2048) AS neutral FROM space_repo WHERE space_ref = ?').bind(SPACE).first())?.neutral).toBe(1);
  });
  it('completes an empty Space with no repo head', async () => {
    const env = await fixture([]), handle = await begin(env);
    for (let sequence = 0; sequence < 3; sequence++) {
      const result = await stepPersonalSpaceDeletion(env, handle, sequence, crypto.randomUUID());
      expect(result.tag).toBe(sequence === 2 ? 'complete' : 'progress');
    }
    expect(await count(env, 'space_repo')).toBe(0);
    expect((await getPersonalSpaceDeletion(env, handle))?.status).toBe('complete');
  });
  it('refuses deletion when a mutation attempt or quarantine receipt retains hash state', async () => {
    const env = await fixture(['a']);
    await env.ALTERAN_DB.prepare(`INSERT INTO space_mutation_attempt
      SELECT 'orphan', space_ref, repo_did, active_epoch_id, generation, rev, set_hash FROM space_repo WHERE space_ref = ?`).bind(SPACE).run();
    expect((await beginPersonalSpaceDeletion(env, SPACE, crypto.randomUUID())).tag).toBe('unavailable');
    expect(await count(env, 'space_personal_deletion_job')).toBe(0);
    await env.ALTERAN_DB.exec("DELETE FROM space_mutation_attempt WHERE mutation_id = 'orphan'");
    await env.ALTERAN_DB.exec('DROP TRIGGER space_quarantine_job_insert_guard');
    await env.ALTERAN_DB.prepare(`INSERT INTO space_quarantine_job
      (id, token, renewal_nonce, space_ref, repo_did, epoch_id, authority_did, space_type, skey,
       generation, mutation_id, rev, expected_hash, accumulated_hash, cursor, sequence, record_count, lease_until, status, activation_nonce, created_at)
      SELECT 'receipt', 'token', 'renewal', space_ref, repo_did, active_epoch_id, repo_did, 'com.example.notes', 'lifecycle',
       generation, mutation_id, rev, set_hash, set_hash, '', 0, 0, 0, 'active', 'activation', 1
      FROM space_repo WHERE space_ref = ?`).bind(SPACE).run();
    expect((await beginPersonalSpaceDeletion(env, SPACE, crypto.randomUUID())).tag).toBe('unavailable');
    expect(await count(env, 'space_personal_deletion_job')).toBe(0);
    expect((await env.ALTERAN_DB.prepare('SELECT state FROM space_epoch').first())?.state).toBe('active');
  });
  it('does not complete an in-flight export if deletion precedes its EOF lease read', async () => {
    const env = await fixture(['a']);
    let resume!: () => void, paused!: () => void;
    const wait = new Promise<void>((resolve) => resume = resolve), ready = new Promise<void>((resolve) => paused = resolve);
    let blocked = false;
    const database = env.ALTERAN_DB;
    const watched = { ...env, ALTERAN_DB: new Proxy(database, { get(target, key) {
      if (key === 'batch') return async (statements: Parameters<typeof database.batch>[0]) => {
        const result = await database.batch(statements);
        if (!blocked && statements.length === 2) { blocked = true; paused(); await wait; }
        return result;
      };
      const value = Reflect.get(target, key, target); return typeof value === 'function' ? value.bind(target) : value;
    } }) };
    const archive = await streamSpaceRepoArchive(watched, SPACE, DID);
    const draining = new Response(archive.body).arrayBuffer();
    await ready;
    await begin(env);
    resume();
    await rejected(() => draining);
    expect(await count(env, 'space_snapshot_lease')).toBe(0);
  });
});
