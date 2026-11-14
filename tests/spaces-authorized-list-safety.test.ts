import { expect } from '@std/expect';
import { describe, it } from './helpers/bdd';
import { authorizedReadFixture, interceptRead, COLLECTION, DID, SPACE } from './helpers/spaces-authorized-read';
import { signResourceDpop } from './helpers/oauth';
import { verifyResourceRequest } from '../src/lib/oauth/resource';
import { loadActiveSpaceOwner } from '../src/db/space-owner';
import { applySpaceWrites } from '../src/db/space-store';
import { listAuthorizedSpaceRecords } from '../src/db/space-authorized-list';

const ENDPOINT = 'https://pds.example/xrpc/com.atproto.space.listRecords';
type Fixture = Awaited<ReturnType<typeof authorizedReadFixture>>;

async function list(f: Fixture, env: Fixture['env'] = f.env, params: Record<string, string> = {}) {
  const query = new URLSearchParams({ space: SPACE, repo: DID, excludeValues: 'true', ...params });
  const request = new Request(`${ENDPOINT}?${query}`, { headers: {
    authorization: `DPoP ${f.tokens.accessJwt}`,
    dpop: await signResourceDpop(env, f.key, 'GET', ENDPOINT, f.tokens.accessJwt),
  } });
  const auth = await verifyResourceRequest(env, request);
  if (!auth?.spacePrincipal) throw new Error('Missing list principal');
  return { request, read: () => listAuthorizedSpaceRecords(env, auth.spacePrincipal, request) };
}

async function allowCorruption(f: Fixture) {
  for (const name of ['space_record_fence_update', 'space_record_version_update_guard', 'space_version_fence_update']) {
    await f.env.ALTERAN_DB.prepare(`DROP TRIGGER ${name}`).run();
  }
}

describe('bounded Space metadata listing', () => {
  it('rejects mismatched current-version bytes without projecting record values', async () => {
    const f = await authorizedReadFixture();
    await allowCorruption(f);
    await f.env.ALTERAN_DB.prepare(`UPDATE space_record_version SET value_cbor = zeroblob(length(value_cbor))
      WHERE space_ref = ? AND collection = ?`).bind(SPACE, COLLECTION).run();
    const watched = interceptRead(f.env);
    const current = await list(f, watched.env);
    watched.arm();
    const result = await current.read();
    expect(result.tag).toBe('invalid');
    expect(JSON.stringify(watched.returned())).not.toContain('value_cbor');
    if (result.tag !== 'invalid') throw new Error('Expected invalid data');
    expect(await result.complete(current.request, watched.env.ALTERAN_DB)).toBe(true);
    const revoked = await list(f, watched.env);
    const invalid = await revoked.read();
    if (invalid.tag !== 'invalid') throw new Error('Expected invalid data');
    await f.env.ALTERAN_DB.prepare('UPDATE oauth_session SET revoked_at = unixepoch() WHERE id = ?').bind(f.sessionId).run();
    expect(await invalid.complete(revoked.request, watched.env.ALTERAN_DB)).toBe(false);
  });

  it('does not transfer embedded-NUL oversized metadata from D1', async () => {
    const f = await authorizedReadFixture();
    await allowCorruption(f);
    const text = `x\u0000${'y'.repeat(400_000)}`;
    await f.env.ALTERAN_DB.prepare('UPDATE space_record SET cid = ? WHERE space_ref = ? AND collection = ?')
      .bind(text, SPACE, COLLECTION).run();
    await f.env.ALTERAN_DB.prepare('UPDATE space_record_version SET cid = ? WHERE space_ref = ? AND collection = ?')
      .bind(text, SPACE, COLLECTION).run();
    const watched = interceptRead(f.env);
    const current = await list(f, watched.env);
    watched.arm();
    const result = await current.read();
    expect(result.tag).toBe('invalid');
    expect(JSON.stringify(watched.returned()).length).toBeLessThan(2_000);
    if (result.tag !== 'invalid') throw new Error('Expected invalid data');
    expect(await result.complete(current.request, watched.env.ALTERAN_DB)).toBe(true);
  });

  it('bounds aggregate record comparison before projecting page metadata', async () => {
    const f = await authorizedReadFixture();
    const owner = await loadActiveSpaceOwner(f.env, DID);
    if (!owner) throw new Error('Missing owner');
    for (let i = 0; i < 5; i++) {
      await applySpaceWrites(f.env, SPACE, DID, [{ action: 'create', collection: COLLECTION, rkey: `large${i}`,
        record: { $type: COLLECTION, text: 'x'.repeat(850_000) } }], owner.incarnation);
    }
    const watched = interceptRead(f.env);
    const current = await list(f, watched.env);
    watched.arm();
    const result = await current.read();
    expect(result.tag).toBe('tooLarge');
    expect(JSON.stringify(watched.returned()).length).toBeLessThan(1_000);
    if (result.tag !== 'tooLarge') throw new Error('Expected bounded page');
    expect(await result.complete(current.request, watched.env.ALTERAN_DB)).toBe(true);
    const smaller = await list(f, watched.env, { limit: '1' });
    const page = await smaller.read();
    if (page.tag !== 'found') throw new Error('Expected smaller page');
    expect(page.records).toHaveLength(1);
    expect(await page.complete(smaller.request, watched.env.ALTERAN_DB)).toBe(true);
    const revoked = await list(f, watched.env);
    const large = await revoked.read();
    if (large.tag !== 'tooLarge') throw new Error('Expected bounded page');
    await f.env.ALTERAN_DB.prepare('UPDATE oauth_session SET revoked_at = unixepoch() WHERE id = ?').bind(f.sessionId).run();
    expect(await large.complete(revoked.request, watched.env.ALTERAN_DB)).toBe(false);
  });
});
