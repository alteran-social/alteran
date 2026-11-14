import { expect } from '@std/expect';
import { DID, interceptRead } from './helpers/spaces-authorized-read';
import { EMPTY, policyFixture } from './helpers/spaces-policy-read';
import { listContext, signedGenesisRequest } from './helpers/spaces-list-genesis';
import { GET } from '../src/pages/xrpc/com.atproto.space.listRecords';

Deno.test('history inserted after selection changes the final batch witness', async () => {
  const f = await policyFixture();
  const db = f.env.ALTERAN_DB;
  let result: unknown[] = [];
  const watched = interceptRead(f.env, { before: async () => {
    await db.prepare('DROP TRIGGER space_epoch_fence_insert').run();
    await db.prepare('DROP TRIGGER space_epoch_owner_insert').run();
    await db.exec(`CREATE TRIGGER test_history_after_page AFTER UPDATE ON oauth_replay_clock
      WHEN OLD.nonce = NEW.nonce BEGIN
        INSERT INTO space_epoch (id, space_ref, repo_did, state, created_at)
        VALUES ('review-history', '${EMPTY}', '${DID}', 'retired', 0);
      END`.replaceAll('\n', ' '));
  }, after: (results) => { result = results; } });
  const request = await signedGenesisRequest(f, { env: watched.env });
  watched.arm();
  const response = await GET(listContext(watched.env, request));
  expect(response.status).toBe(401);
  const selected = (result[2] as { results: Record<string, unknown>[] }).results;
  const final = (result[5] as { results: Record<string, unknown>[] }).results;
  expect(selected).toHaveLength(1);
  expect(selected[0].sentinel).toBe(1);
  expect(selected[0].epoch_id).toBeNull();
  expect(selected[0].budget_total).toBe(0);
  expect(typeof selected[0].genesis_nonce).toBe('string');
  expect(final).toHaveLength(1);
  expect(typeof final[0].session_expires_at).toBe('number');
  expect(final[0].epoch_id).toBeNull();
  expect(final[0].genesis_nonce === null).toBe(true);
  expect(final[0].genesis_created_at).toBeNull();
  const inserted = await db.prepare("SELECT COUNT(*) AS n FROM space_epoch WHERE id = 'review-history'").first<{ n: number }>();
  expect(inserted?.n).toBe(1);
});
