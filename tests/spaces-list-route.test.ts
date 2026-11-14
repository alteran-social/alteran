import { expect } from '@std/expect';
import { describe, it } from './helpers/bdd';
import { authorizedReadFixture, interceptRead, COLLECTION, DID, OTHER_COLLECTION, SPACE } from './helpers/spaces-authorized-read';
import { makeDpopKey, signResourceDpop } from './helpers/oauth';
import { createOAuthSession } from './helpers/oauth-store';
import { issueSessionTokens } from '../src/lib/session-tokens';
import { GET, HEAD, ALL } from '../src/pages/xrpc/com.atproto.space.listRecords';

const PATH = 'https://pds.example/xrpc/com.atproto.space.listRecords';
const PARAMS = { space: SPACE, repo: DID, excludeValues: 'true' };
type Fixture = Awaited<ReturnType<typeof authorizedReadFixture>>;
type TestEnv = Fixture['env'];

function context(env: TestEnv, request: Request) {
  return { locals: { env }, request, url: new URL(request.url) } as never;
}

async function signedRequest(f: Fixture, params: Record<string, string> = {}, options: {
  env?: TestEnv; token?: string; key?: Fixture['key']; proof?: string; query?: string;
  signal?: AbortSignal; headers?: HeadersInit;
} = {}): Promise<Request> {
  const token = options.token ?? f.tokens.accessJwt;
  const proof = options.proof ?? await signResourceDpop(options.env ?? f.env, options.key ?? f.key, 'GET', PATH, token);
  const headers = new Headers(options.headers);
  headers.set('authorization', `DPoP ${token}`);
  headers.set('dpop', proof);
  return new Request(`${PATH}?${options.query ?? new URLSearchParams({ ...PARAMS, ...params })}`, {
    headers, signal: options.signal,
  });
}

function assertPrivate(response: Response) {
  expect(response.headers.get('cache-control')).toBe('private, no-store');
  const vary = (response.headers.get('vary') ?? '').toLowerCase().split(',').map((item) => item.trim());
  for (const name of ['accept-signature', 'authorization', 'dpop']) expect(vary).toContain(name);
}

/** Observe the page SELECT after it commits while retaining the real D1 binding. */
function watchPage(f: Fixture, action: (rows: Record<string, unknown>[]) => Promise<void> | void) {
  let seen = false;
  const watched = interceptRead(f.env, { after: async (result) => {
    const rows = (result[2] as { results?: Record<string, unknown>[] } | undefined)?.results;
    if (seen || !Array.isArray(rows) || !rows.some((row) => row.sentinel === 1)) return;
    seen = true;
    await action(rows);
  } });
  return { ...watched, seen: () => seen };
}

function failCompletion(env: TestEnv): TestEnv {
  const database = env.ALTERAN_DB;
  const wrapped = new Proxy(database, { get(target, key) {
    if (key === 'prepare') return (sql: string) => {
      const statement = database.prepare(sql);
      if (!sql.includes('RETURNING seconds, nonce')) return statement;
      return new Proxy(statement, { get(prepared, property) {
        if (property === 'bind') return (...values: Parameters<typeof prepared.bind>) => {
          const bound = prepared.bind(...values);
          return new Proxy(bound, { get(boundTarget, boundKey) {
            if (boundKey === 'first') return async () => { throw new Error('private completion failure'); };
            const value = Reflect.get(boundTarget, boundKey, boundTarget);
            return typeof value === 'function' ? value.bind(boundTarget) : value;
          } });
        };
        const value = Reflect.get(prepared, property, prepared);
        return typeof value === 'function' ? value.bind(prepared) : value;
      } });
    };
    const value = Reflect.get(target, key, target);
    return typeof value === 'function' ? value.bind(target) : value;
  } });
  return { ...env, ALTERAN_DB: wrapped };
}

function switchDatabaseAfterCompletion(env: TestEnv) {
  const database = env.ALTERAN_DB;
  const watched = { ...env };
  let changed = false;
  const wrapped = new Proxy(database, { get(target, key) {
    if (key === 'prepare') return (sql: string) => {
      const statement = database.prepare(sql);
      if (!sql.includes('SELECT clock.seconds, authorized.session_expires_at')) return statement;
      return new Proxy(statement, { get(prepared, property) {
        if (property === 'bind') return (...values: Parameters<typeof prepared.bind>) => {
          const bound = prepared.bind(...values);
          return new Proxy(bound, { get(boundTarget, boundKey) {
            if (boundKey === 'first') return async () => {
              const row = await bound.first();
              watched.ALTERAN_DB = new Proxy(database, {});
              changed = true;
              return row;
            };
            const value = Reflect.get(boundTarget, boundKey, boundTarget);
            return typeof value === 'function' ? value.bind(boundTarget) : value;
          } });
        };
        const value = Reflect.get(prepared, property, prepared);
        return typeof value === 'function' ? value.bind(prepared) : value;
      } });
    };
    const value = Reflect.get(target, key, target);
    return typeof value === 'function' ? value.bind(target) : value;
  } });
  watched.ALTERAN_DB = wrapped;
  return { env: watched, changed: () => changed };
}

describe('owner-only Space listRecords route', () => {
  it('returns metadata-only pages with reference cursor order', async () => {
    const f = await authorizedReadFixture();
    const first = await GET(context(f.env, await signedRequest(f, { limit: '1' })));
    expect(first.status).toBe(200);
    assertPrivate(first);
    const page1 = await first.json() as { records: { collection: string; rkey: string; cid: string }[]; cursor: string };
    expect(page1.records.map(({ collection, rkey }) => `${collection}/${rkey}`)).toEqual([`${OTHER_COLLECTION}/two`]);
    expect(Object.keys(page1.records[0]).sort()).toEqual(['cid', 'collection', 'rkey']);
    expect(typeof page1.cursor).toBe('string');

    const second = await GET(context(f.env, await signedRequest(f, { limit: '1', cursor: page1.cursor })));
    expect(second.status).toBe(200);
    const page2 = await second.json() as { records: { collection: string; rkey: string }[]; cursor: string };
    expect(page2.records.map(({ collection, rkey }) => `${collection}/${rkey}`)).toEqual([`${COLLECTION}/one`]);
    const end = await GET(context(f.env, await signedRequest(f, { limit: '1', cursor: page2.cursor })));
    expect(await end.json()).toEqual({ records: [] });
    const filtered = await GET(context(f.env, await signedRequest(f, { collection: COLLECTION })));
    expect(filtered.status).toBe(200);
    const filteredPage = await filtered.json() as { records: { collection: string; rkey: string }[] };
    expect(filteredPage.records.map(({ collection, rkey }) => `${collection}/${rkey}`)).toEqual([`${COLLECTION}/one`]);
  });

  it('validates request, signature and credential bounds before access', async () => {
    const f = await authorizedReadFixture();
    const valid = await signedRequest(f);
    const proof = valid.headers.get('dpop') ?? '';
    const query = new URLSearchParams(PARAMS).toString();
    for (const candidate of [`${query}&repo=${encodeURIComponent(DID)}`, `${query}&unknown=1`,
      `${query}&limit=51`, `${query}&cursor=invalid`, `space=${'x'.repeat(17_000)}`]) {
      const response = await GET(context(f.env, await signedRequest(f, {}, { query: candidate, proof })));
      expect(response.status).toBe(400);
      assertPrivate(response);
    }
    const invalidCursor = await GET(context(f.env, await signedRequest(f, { cursor: 'invalid' }, { proof })));
    expect((await invalidCursor.json() as { error: string }).error).toBe('InvalidCursor');
    for (const signature of ['', 'invalid', 'sig1=("@method");keyid="example"']) {
      const response = await GET(context(f.env, await signedRequest(f, {}, { proof, headers: { 'accept-signature': signature } })));
      expect(response.status).toBe(400);
      expect((await response.json() as { error: string }).error).toBe('InvalidSpaceMac');
    }
    const largeAuth = new Request(`${PATH}?${query}`, { headers: { authorization: `DPoP ${'a'.repeat(65_536)}` } });
    const largeProof = new Request(`${PATH}?${query}`, { headers: { authorization: 'DPoP token', dpop: 'x'.repeat(16_385) } });
    for (const request of [largeAuth, largeProof]) expect((await GET(context(f.env, request))).status).toBe(400);
    const noAuth = await GET(context(f.env, new Request(`${PATH}?${query}`)));
    expect(noAuth.status).toBe(401);
    expect(noAuth.headers.get('www-authenticate')).toBe('DPoP');
    const noProof = await GET(context(f.env, new Request(`${PATH}?${query}`, { headers: { authorization: `DPoP ${f.tokens.accessJwt}` } })));
    expect(noProof.status).toBe(401);
    expect(noProof.headers.get('dpop-nonce')).toBeTruthy();
    const exposed = (noProof.headers.get('access-control-expose-headers') ?? '').toLowerCase();
    expect(exposed).toContain('dpop-nonce');
    expect(exposed).toContain('www-authenticate');
    expect((await GET(context(f.env, await signedRequest(f, {}, { proof })))).status).toBe(200);
    expect(HEAD().status).toBe(405);
    expect(ALL().status).toBe(405);
    assertPrivate(HEAD());
  });

  it('enforces repository ownership, grant target and proof replay', async () => {
    const f = await authorizedReadFixture();
    const crossRepo = await GET(context(f.env, await signedRequest(f, { repo: 'did:example:other' })));
    expect(crossRepo.status).toBe(400);
    expect((await crossRepo.json() as { error: string }).error).toBe('RepoNotFound');
    const outsideGrant = await GET(context(f.env, await signedRequest(f, {
      space: `at://${DID}/space/com.example.notes/not-granted`,
    })));
    expect(outsideGrant.status).toBe(401);
    const first = await signedRequest(f, { limit: '1' });
    const proof = first.headers.get('dpop') ?? '';
    expect((await GET(context(f.env, first))).status).toBe(200);
    const replay = await GET(context(f.env, await signedRequest(f, { collection: COLLECTION }, { proof })));
    expect(replay.status).toBe(400);
    expect((await replay.json() as { error: string }).error).toBe('InvalidToken');

    const key = await makeDpopKey();
    const sessionId = crypto.randomUUID(), accessJti = crypto.randomUUID(), clientId = 'https://client.example/metadata';
    const token = await issueSessionTokens(f.env, DID, {
      clientId, dpopJkt: key.jkt, oauthSessionId: sessionId, accessJti, accessScope: 'atproto transition:generic',
    });
    await createOAuthSession(f.env, { id: sessionId, did: DID, clientId, clientAuthMethod: 'none', dpopJkt: key.jkt,
      scope: 'atproto transition:generic', currentRefreshTokenId: token.refreshPayload.jti,
      accessJti, expiresAt: token.refreshExpiry });
    const noGrant = await GET(context(f.env, await signedRequest(f, {}, { token: token.accessJwt, key })));
    expect(noGrant.status).toBe(403);
    expect((await noGrant.json() as { error: string }).error).toBe('ScopeMissingError');
  });

  it('gates found, invalid and oversized pages on post-selection authorization', async () => {
    for (const mode of ['found', 'invalid', 'tooLarge'] as const) {
      for (const revoke of [false, true]) {
        const f = await authorizedReadFixture();
        const watched = watchPage(f, async (rows) => {
          const sentinel = rows.find((row) => row.sentinel === 1);
          const record = rows.find((row) => row.sentinel === 0);
          if (!sentinel || !record) throw new Error('Missing selected page');
          if (mode === 'invalid') record.cid = 'not-a-cid';
          if (mode === 'tooLarge') {
            sentinel.too_large = 1;
            rows.splice(0, rows.length, sentinel);
          }
          if (revoke) await f.env.ALTERAN_DB.prepare('UPDATE oauth_session SET revoked_at = unixepoch() WHERE id = ?')
            .bind(f.sessionId).run();
        });
        const request = await signedRequest(f, {}, { env: watched.env });
        watched.arm();
        const response = await GET(context(watched.env, request));
        expect(watched.seen()).toBe(true);
        expect(response.status).toBe(revoke ? 401 : mode === 'found' ? 200 : mode === 'invalid' ? 500 : 400);
        const body = await response.text();
        if (revoke) expect(body).not.toContain('cid');
        expect(body).not.toContain('not-a-cid');
        assertPrivate(response);
      }
    }
  });

  it('withholds empty pages after revocation and stops cancelled requests', async () => {
    for (const mode of ['empty-revoked', 'cancelled'] as const) {
      const f = await authorizedReadFixture();
      const controller = new AbortController();
      const watched = watchPage(f, async () => {
        if (mode === 'cancelled') controller.abort();
        else await f.env.ALTERAN_DB.prepare('UPDATE oauth_session SET revoked_at = unixepoch() WHERE id = ?')
          .bind(f.sessionId).run();
      });
      const request = await signedRequest(f, mode === 'empty-revoked' ? { collection: 'com.example.empty' } : {}, {
        env: watched.env, signal: controller.signal,
      });
      watched.arm();
      const response = await GET(context(watched.env, request));
      expect(watched.seen()).toBe(true);
      expect(response.status).toBe(401);
      expect(await response.text()).not.toContain('records');
      assertPrivate(response);
    }
  });

  it('withholds a page when the D1 binding changes during completion', async () => {
    const f = await authorizedReadFixture();
    const watched = switchDatabaseAfterCompletion(f.env);
    const response = await GET(context(watched.env, await signedRequest(f, {}, { env: watched.env })));
    expect(watched.changed()).toBe(true);
    expect(response.status).toBe(401);
    expect(await response.text()).not.toContain('records');
    assertPrivate(response);
  });

  it('gates serialization failures and fails closed on completion faults', async () => {
    for (const revoke of [false, true]) {
      const f = await authorizedReadFixture();
      const original = JSON.stringify;
      const watched = watchPage(f, async () => {
        if (revoke) await f.env.ALTERAN_DB.prepare('UPDATE oauth_session SET revoked_at = unixepoch() WHERE id = ?')
          .bind(f.sessionId).run();
        JSON.stringify = ((...args: Parameters<typeof JSON.stringify>) => {
          const value = args[0];
          if (value && typeof value === 'object' && 'records' in value) throw new Error('private serialization failure');
          return Reflect.apply(original, JSON, args);
        }) as typeof JSON.stringify;
      });
      try {
        const request = await signedRequest(f, {}, { env: watched.env });
        watched.arm();
        const response = await GET(context(watched.env, request));
        expect(watched.seen()).toBe(true);
        expect(response.status).toBe(revoke ? 401 : 500);
        expect(await response.text()).not.toContain('private serialization failure');
        assertPrivate(response);
      } finally {
        JSON.stringify = original;
      }
    }
    const f = await authorizedReadFixture();
    const faulted = failCompletion(f.env);
    const response = await GET(context(faulted, await signedRequest(f, {}, { env: faulted })));
    expect(response.status).toBe(401);
    expect(await response.text()).not.toContain('private completion failure');
    assertPrivate(response);
  });
});
