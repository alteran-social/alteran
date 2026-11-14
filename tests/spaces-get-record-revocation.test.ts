import { expect } from '@std/expect';
import { describe, it } from './helpers/bdd';
import { authorizedReadFixture, interceptRead, COLLECTION, DID, SPACE } from './helpers/spaces-authorized-read';
import { signResourceDpop } from './helpers/oauth';
import { GET } from '../src/pages/xrpc/com.atproto.space.getRecord';

const ENDPOINT = 'https://pds.example/xrpc/com.atproto.space.getRecord';
type Fixture = Awaited<ReturnType<typeof authorizedReadFixture>>;

async function signed(f: Fixture, rkey: string) {
  const query = new URLSearchParams({ space: SPACE, repo: DID, collection: COLLECTION, rkey });
  return new Request(`${ENDPOINT}?${query}`, { headers: {
    authorization: `DPoP ${f.tokens.accessJwt}`,
    dpop: await signResourceDpop(f.env, f.key, 'GET', ENDPOINT, f.tokens.accessJwt),
  } });
}

async function corrupt(f: Fixture) {
  for (const name of ['space_record_fence_update', 'space_record_version_update_guard', 'space_version_fence_update']) {
    await f.env.ALTERAN_DB.prepare(`DROP TRIGGER ${name}`).run();
  }
  await f.env.ALTERAN_DB.prepare('UPDATE space_record SET cid = ? WHERE space_ref = ? AND collection = ?')
    .bind('corrupt', SPACE, COLLECTION).run();
  await f.env.ALTERAN_DB.prepare('UPDATE space_record_version SET cid = ? WHERE space_ref = ? AND collection = ?')
    .bind('corrupt', SPACE, COLLECTION).run();
}

function context(env: Fixture['env'], request: Request) {
  return { locals: { env }, request, url: new URL(request.url) } as never;
}

describe('Space record errors and revocation', () => {
  it('does not expose the presence of a corrupt record after post-selection revocation', async () => {
    for (const mode of ['valid', 'missing', 'corrupt'] as const) {
      const f = await authorizedReadFixture();
      if (mode === 'corrupt') await corrupt(f);
      const watched = interceptRead(f.env, { after: async () => {
        await f.env.ALTERAN_DB.prepare('UPDATE oauth_session SET revoked_at = unixepoch() WHERE id = ?').bind(f.sessionId).run();
      } });
      const request = await signed(f, mode === 'missing' ? 'missing' : 'one');
      watched.arm();
      const response = await GET(context(watched.env, request));
      expect(response.status).toBe(401);
      expect(response.headers.get('cache-control')).toBe('private, no-store');
      expect(await response.json()).toEqual({ error: 'AuthRequired', message: 'Authentication required' });
    }
    const f = await authorizedReadFixture();
    await corrupt(f);
    const response = await GET(context(f.env, await signed(f, 'one')));
    expect(response.status).toBe(500);
    expect(await response.json()).toEqual({ error: 'InternalServerError', message: 'Internal server error' });
  });

  it('rechecks authorization after a record response serialization failure', async () => {
    for (const revoke of [false, true]) {
      const f = await authorizedReadFixture();
      const uri = `${SPACE}/${DID}/${COLLECTION}/one`;
      const original = JSON.stringify;
      const watched = interceptRead(f.env, { after: async () => {
        if (revoke) {
          await f.env.ALTERAN_DB.prepare('UPDATE oauth_session SET revoked_at = unixepoch() WHERE id = ?').bind(f.sessionId).run();
        }
        JSON.stringify = ((value: unknown, ...args: unknown[]) => {
          if (value === uri) throw new Error('private serialization failure');
          return Reflect.apply(original, JSON, [value, ...args]);
        }) as typeof JSON.stringify;
      } });
      const request = await signed(f, 'one');
      watched.arm();
      try {
        const response = await GET(context(watched.env, request));
        expect(response.status).toBe(revoke ? 401 : 500);
        expect(await response.text()).not.toContain('private serialization failure');
      } finally {
        JSON.stringify = original;
      }
    }
  });

  it('denies if the database binding changes after record selection', async () => {
    const f = await authorizedReadFixture();
    const watched = interceptRead(f.env, { after: () => {
      watched.env.ALTERAN_DB = new Proxy(f.env.ALTERAN_DB, {});
    } });
    const request = await signed(f, 'one');
    watched.arm();
    const response = await GET(context(watched.env, request));
    expect(response.status).toBe(401);
    expect(await response.text()).not.toContain('private');
  });
});
