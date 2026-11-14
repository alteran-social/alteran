import { expect } from '@std/expect';
import { DID } from './helpers/spaces-authorized-read';
import { EMPTY, policyFixture } from './helpers/spaces-policy-read';
import { listContext, signedGenesisRequest } from './helpers/spaces-list-genesis';
import { GET } from '../src/pages/xrpc/com.atproto.space.listRecords';

const HISTORY = [
  ['space_repo', `INSERT INTO space_repo (space_ref, repo_did, set_hash, generation, mutation_id)
    VALUES (?, ?, zeroblob(2048), 1, 'historical')`],
  ['space_epoch', `INSERT INTO space_epoch (id, space_ref, repo_did, state, created_at)
    VALUES ('historical', ?, ?, 'retired', 0)`],
  ['space_record', `INSERT INTO space_record (space_ref, repo_did, collection, rkey, cid, value_cbor, repo_rev)
    VALUES (?, ?, 'com.example.note', 'old', 'cid', x'01', 'revision')`],
  ['space_op', `INSERT INTO space_op (space_ref, repo_did, rev, ordinal, collection, rkey)
    VALUES (?, ?, 'revision', 0, 'com.example.note', 'old')`],
  ['space_record_version', `INSERT INTO space_record_version (epoch_id, space_ref, repo_did, path, collection, rkey,
      from_generation, cid, value_cbor, value_size, repo_rev)
    VALUES ('historical', ?, ?, 'com.example.note/old', 'com.example.note', 'old', 1, 'cid', x'01', 1, 'revision')`],
  ['space_blob_usage', `INSERT INTO space_blob_usage (space_ref, repo_did, collection, rkey, cid, key)
    VALUES (?, ?, 'com.example.note', 'old', 'cid', 'key')`],
  ['space_snapshot_lease', `INSERT INTO space_snapshot_lease (id, token, renewal_nonce, space_ref, repo_did, epoch_id,
      generation, rev, set_hash, expires_at, maximum_expires_at)
    VALUES ('historical', 'token', 'renewal', ?, ?, 'old', 1, 'revision', zeroblob(2048), 1, 2)`],
  ['space_gc_attempt', `INSERT INTO space_gc_attempt (id, space_ref, repo_did, epoch_id) VALUES ('historical', ?, ?, 'old')`],
  ['space_quarantine_job', `INSERT INTO space_quarantine_job (id, token, renewal_nonce, space_ref, repo_did, epoch_id,
      authority_did, space_type, skey, generation, mutation_id, rev, expected_hash, accumulated_hash, cursor, sequence,
      record_count, lease_until, status, created_at)
    VALUES ('historical', 'token', 'renewal', ?, ?, 'old', 'did:example:test', 'com.example.notes', 'empty-policy',
      1, 'mutation', 'revision', zeroblob(2048), zeroblob(2048), '', 0, 0, 1, 'failed', 0)`],
  ['space_mutation_attempt', `INSERT INTO space_mutation_attempt (mutation_id, space_ref, repo_did, epoch_id, generation, rev, set_hash)
    VALUES ('historical', ?, ?, 'old', 1, 'revision', zeroblob(2048))`],
  ['space_personal_creation_attempt', `INSERT INTO space_personal_creation_attempt
      (nonce, space_ref, authority_did, space_type, skey, created_at)
    VALUES ('historical', ?, ?, 'com.example.notes', 'empty-policy', 0)`],
  ['space_personal_deletion_job', `INSERT INTO space_personal_deletion_job
      (nonce, space_ref, authority_did, status, phase, sequence, last_step_count, created_at)
    VALUES ('historical', ?, ?, 'complete', 'done', 0, 0, 0)`],
  ['space_personal_deletion_attempt', `INSERT INTO space_personal_deletion_attempt
      (nonce, job_nonce, space_ref, authority_did, phase, sequence, status, maximum_count, expected_count, expected_bytes)
    VALUES ('historical', 'job', ?, ?, 'records', 0, 'building', 1, 0, 0)`],
] as const;

Deno.test('every retained history category prevents a genesis list', async () => {
  const f = await policyFixture();
  const db = f.env.ALTERAN_DB;
  for (const [table, insert] of HISTORY) {
    const triggers = await db.prepare("SELECT name FROM sqlite_master WHERE type = 'trigger' AND tbl_name = ?")
      .bind(table).all<{ name: string }>();
    for (const trigger of triggers.results) {
      await db.prepare(`DROP TRIGGER "${trigger.name.replaceAll('"', '""')}"`).run();
    }
    await db.prepare(insert).bind(EMPTY, DID).run();
    const request = await signedGenesisRequest(f);
    const response = await GET(listContext(f.env, request));
    expect(response.status).toBe(401);
    expect(await response.text()).not.toContain('records');
    await db.prepare(`DELETE FROM ${table} WHERE space_ref = ?`).bind(EMPTY).run();
    const retry = await signedGenesisRequest(f);
    expect((await GET(listContext(f.env, retry))).status).toBe(200);
  }
  await db.prepare(`INSERT INTO space_op (space_ref, repo_did, rev, ordinal, collection, rkey)
    VALUES (?, 'did:example:other', 'revision', 0, 'com.example.note', 'old')`).bind(EMPTY).run();
  const anotherRepo = await signedGenesisRequest(f);
  expect((await GET(listContext(f.env, anotherRepo))).status).toBe(200);
});
