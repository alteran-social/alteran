import { expect } from '@std/expect';
import { afterEach, describe, it } from './helpers/bdd';
import { applyPrivateBlobMigrations, disposePrivateBlobEnv, makePrivateBlobEnv } from './helpers/private-blob-env';
import { preparePrivateBlobReservation, reservePrivateBlob } from '../src/lib/spaces/private-blob-staging';

const DID = 'did:example:test';
async function rejected(operation: () => Promise<unknown>) {
  let failed = false;
  try { await operation(); } catch { failed = true; }
  expect(failed).toBe(true);
}

describe('private blob staging migration', () => {
  afterEach(disposePrivateBlobEnv);
  it('upgrades populated 0039 without changing accounts, public blobs, or legacy Spaces', async () => {
    const env = await makePrivateBlobEnv(39);
    await env.ALTERAN_DB.prepare('INSERT INTO account (did,handle,created_at,updated_at) VALUES (?, ?, 1, 1)').bind(DID, 'test.example').run();
    await env.ALTERAN_DB.prepare('INSERT INTO account_state (did,active,created_at) VALUES (?,1,1)').bind(DID).run();
    const before = await env.ALTERAN_DB.prepare('SELECT space_incarnation FROM account WHERE did = ?').bind(DID).first<{space_incarnation: string}>();
    await env.ALTERAN_DB.prepare(`INSERT INTO blob (did,cid,key,mime,size,uploaded_at) VALUES (?, 'legacy-cid', 'legacy-key', 'text/plain', 3, 1)`).bind(DID).run();
    await env.ALTERAN_DB.prepare(`INSERT INTO blob_usage (did,record_uri,key,cid,repo_rev) VALUES (?, 'at://did:example:test/com.example.post/one', 'legacy-key', 'legacy-cid', 'legacy-rev')`).bind(DID).run();
    await env.PUBLIC_BLOBS.put('legacy-key', 'old');
    await env.ALTERAN_DB.prepare(`INSERT INTO space (space_ref,authority_did,space_type,skey,created_at)
      VALUES ('at://did:example:test/space/com.example.space/legacy', ?, 'com.example.space', 'legacy', 1)`).bind(DID).run();
    await applyPrivateBlobMigrations(env.ALTERAN_DB, 40, 41);
    expect(await env.ALTERAN_DB.prepare('SELECT space_incarnation FROM account WHERE did = ?').bind(DID).first()).toEqual(before);
    expect((await env.ALTERAN_DB.prepare('SELECT COUNT(*) AS n FROM blob_usage').first())?.n).toBe(1);
    expect((await env.ALTERAN_DB.prepare('SELECT COUNT(*) AS n FROM space').first())?.n).toBe(1);
    expect(await (await env.PUBLIC_BLOBS.get('legacy-key'))?.text()).toBe('old');
    expect((await env.ALTERAN_DB.prepare('SELECT COUNT(*) AS n FROM private_blob_staging').first())?.n).toBe(0);
    const handle = preparePrivateBlobReservation(DID, before!.space_incarnation);
    expect(handle).not.toBeNull();
    expect((await reservePrivateBlob(env.ALTERAN_DB, handle!)).tag).toBe('reserved');
  });

  it('rolls back a failed guard migration batch and installs guards after retry', async () => {
    const env = await makePrivateBlobEnv(40);
    await env.ALTERAN_DB.exec('CREATE TRIGGER private_blob_staging_update BEFORE UPDATE ON private_blob_staging BEGIN SELECT 1; END');
    await rejected(() => applyPrivateBlobMigrations(env.ALTERAN_DB, 41, 41));
    expect((await env.ALTERAN_DB.prepare("SELECT COUNT(*) AS n FROM sqlite_master WHERE type = 'trigger' AND name = 'private_blob_staging_insert'").first())?.n).toBe(0);
    await env.ALTERAN_DB.exec('DROP TRIGGER private_blob_staging_update');
    await applyPrivateBlobMigrations(env.ALTERAN_DB, 41, 41);
    expect((await env.ALTERAN_DB.prepare("SELECT COUNT(*) AS n FROM sqlite_master WHERE type = 'trigger' AND name LIKE 'private_blob_staging_%'").first())?.n).toBe(3);
  });

  it('refuses to install guards over rows written before the guard migration', async () => {
    const env = await makePrivateBlobEnv(40);
    await env.ALTERAN_DB.prepare(`INSERT INTO private_blob_staging (id, token, repo_did, account_incarnation, object_key, state, reserved_bytes)
      VALUES (?, ?, ?, ?, ?, 'reserved', 5242880)`)
      .bind('a'.repeat(32), 'b'.repeat(32), DID, 'c'.repeat(32), `space-staging/${'a'.repeat(32)}`).run();
    await rejected(() => applyPrivateBlobMigrations(env.ALTERAN_DB, 41, 41));
    expect((await env.ALTERAN_DB.prepare("SELECT COUNT(*) AS n FROM sqlite_master WHERE type = 'trigger' AND name LIKE 'private_blob_staging_%'").first())?.n).toBe(0);
    await env.ALTERAN_DB.prepare('DELETE FROM private_blob_staging').run();
    await applyPrivateBlobMigrations(env.ALTERAN_DB, 41, 41);
    expect((await env.ALTERAN_DB.prepare("SELECT COUNT(*) AS n FROM sqlite_master WHERE type = 'trigger' AND name LIKE 'private_blob_staging_%'").first())?.n).toBe(3);
  });
});
