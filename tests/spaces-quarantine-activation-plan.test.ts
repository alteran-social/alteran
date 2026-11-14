import { expect } from '@std/expect';
import { makeEnv } from './helpers/env';

const OWNER = 'at://did:example:test/space/com.example.notes/plan';
const REPO = 'did:example:test';
const OLD_EOF = `NOT EXISTS (SELECT 1 FROM space_record r
  WHERE r.space_ref = j.space_ref AND r.repo_did = j.repo_did
    AND (r.collection || '/' || r.rkey) COLLATE BINARY > j.cursor COLLATE BINARY)`;
const NEW_EOF = `COALESCE((SELECT (r.collection || '/' || r.rkey) COLLATE BINARY
  FROM space_record r INDEXED BY space_record_path_idx
  WHERE r.space_ref = j.space_ref AND r.repo_did = j.repo_did
  ORDER BY (r.collection || '/' || r.rkey) COLLATE BINARY DESC LIMIT 1)
  > j.cursor COLLATE BINARY, 0) = 0`;
const JOB = 'WITH j(space_ref, repo_did, cursor) AS (VALUES (?, ?, ?))';

Deno.test('quarantine activation EOF uses one indexed reverse seek', async () => {
  const env = await makeEnv();
  await env.ALTERAN_DB.prepare('DROP TRIGGER space_record_fence_insert').run();
  await env.ALTERAN_DB.prepare(`WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i + 1 FROM n WHERE i < 600)
    INSERT INTO space_record (space_ref, repo_did, collection, rkey, cid, value_cbor, repo_rev)
    SELECT ?, ?, 'com.example.note', printf('k%04d', i), 'cid', x'00', '2222222222222' FROM n`)
    .bind(OWNER, REPO).run();
  await env.ALTERAN_DB.prepare(`INSERT INTO space_record
    (space_ref, repo_did, collection, rkey, cid, value_cbor, repo_rev)
    VALUES (?, ?, 'com.example.note', 'z' || char(0) || 'tail', 'cid', x'00', '2222222222222')`)
    .bind(OWNER, REPO).run();
  const compare = env.ALTERAN_DB.prepare(`${JOB} SELECT ${OLD_EOF} AS old, ${NEW_EOF} AS new FROM j`);
  for (const cursor of ['', 'com.example.note/k0001', 'com.example.note/k0300',
    'com.example.note/k0600', 'com.example.note/z\u0000tail', 'com.example.note/zz']) {
    const result = await compare.bind(OWNER, REPO, cursor).first<{ old: number; new: number }>();
    expect(result?.new).toBe(result?.old);
  }
  const empty = await compare.bind(OWNER, 'did:example:other', '').first<{ old: number; new: number }>();
  expect(empty).toEqual({ old: 1, new: 1 });

  const sql = `${JOB} SELECT ${NEW_EOF} AS done FROM j`;
  const cursor = 'com.example.note/zz';
  const result = await env.ALTERAN_DB.prepare(sql).bind(OWNER, REPO, cursor).all();
  expect(result.results).toEqual([{ done: 1 }]);
  expect(result.meta.rows_read).toBeLessThan(50);
  const plan = await env.ALTERAN_DB.prepare(`EXPLAIN ${sql}`).bind(OWNER, REPO, cursor).all<{ opcode: string }>();
  expect(plan.results.some((row) => row.opcode === 'SeekLE')).toBe(true);
});
