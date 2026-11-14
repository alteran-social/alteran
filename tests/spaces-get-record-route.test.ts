import { expect } from '@std/expect';
import { describe, it } from './helpers/bdd';
import { authorizedReadFixture, interceptRead, COLLECTION, DID, OTHER_COLLECTION, SPACE } from './helpers/spaces-authorized-read';
import { makeDpopKey, signResourceDpop } from './helpers/oauth';
import { createOAuthSession } from './helpers/oauth-store';
import { AuthScope } from '../src/lib/auth-scope';
import { issueSessionTokens } from '../src/lib/session-tokens';
import { readAuthorizedSpaceRecord } from '../src/db/space-authorized-record';
import { beginPersonalSpaceDeletion } from './helpers/space-storage';
import { setAccountState } from '../src/db/dal';
import { GET, HEAD, ALL } from '../src/pages/xrpc/com.atproto.space.getRecord';

const PATH = 'https://pds.example/xrpc/com.atproto.space.getRecord';
const TARGET = { space: SPACE, repo: DID, collection: COLLECTION, rkey: 'one' };
type Fixture = Awaited<ReturnType<typeof authorizedReadFixture>>;
type TestEnv = Fixture['env'];

function context(env: TestEnv, request: Request) {
  return { locals: { env }, request, url: new URL(request.url) } as never;
}

async function signedRequest(f: Fixture, target = TARGET, options: {
  proof?: string; token?: string; query?: string; signal?: AbortSignal; headers?: HeadersInit;
} = {}): Promise<Request> {
  const token = options.token ?? f.tokens.accessJwt;
  const proof = options.proof ?? await signResourceDpop(f.env, f.key, 'GET', PATH, token);
  const headers = new Headers(options.headers);
  headers.set('authorization', `DPoP ${token}`);
  headers.set('dpop', proof);
  return new Request(`${PATH}?${options.query ?? new URLSearchParams(target)}`, { headers, signal: options.signal });
}

function assertPrivate(response: Response) {
  expect(response.headers.get('cache-control')).toBe('private, no-store');
  const vary = (response.headers.get('vary') ?? '').toLowerCase().split(',').map((item) => item.trim());
  expect(vary).toContain('accept-signature');
  expect(vary).toContain('authorization');
  expect(vary).toContain('dpop');
}

/** Intercept the post-serialization sample or state check, leaving admission untouched. */
function interceptCompletion(env: TestEnv, options: {
  beforeSample?: () => Promise<void> | void;
  afterSample?: () => Promise<void> | void;
  afterState?: () => Promise<void> | void;
  failState?: boolean;
  missingState?: boolean;
}): TestEnv {
  const database = env.ALTERAN_DB;
  const proxy = new Proxy(database, { get(target, key) {
    if (key === 'prepare') return (sql: string) => {
      const statement = database.prepare(sql);
      const sample = sql.includes('RETURNING seconds, nonce');
      const state = sql.includes('SELECT clock.seconds, authorized.session_expires_at');
      if (!sample && !state) return statement;
      return new Proxy(statement, { get(prepared, property) {
        if (property === 'bind') return (...values: Parameters<typeof prepared.bind>) => {
          const bound = prepared.bind(...values);
          return new Proxy(bound, { get(boundTarget, boundKey) {
            if (boundKey === 'first') return async () => {
              if (sample) await options.beforeSample?.();
              if (state && options.failState) throw new Error('private test failure');
              const result = await bound.first();
              if (sample) await options.afterSample?.();
              if (state) await options.afterState?.();
              return state && options.missingState ? null : result;
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
  return { ...env, ALTERAN_DB: proxy };
}

describe('owner-only Space getRecord route', () => {
  it('returns an unsigned record and rejects a proof replayed across query variants', async () => {
    const f = await authorizedReadFixture();
    const request = await signedRequest(f);
    const proof = request.headers.get('dpop') ?? '';
    const response = await GET(context(f.env, request));
    expect(response.status).toBe(200);
    assertPrivate(response);
    expect(response.headers.get('signature')).toBeNull();
    const body = await response.json() as { uri: string; cid: string; value: unknown };
    expect(body.uri).toBe(`at://${DID}/space/com.example.notes/read-record/${DID}/${COLLECTION}/one`);
    expect(typeof body.cid).toBe('string');
    expect(body.value).toEqual({ $type: COLLECTION, text: 'private' });

    const replay = await GET(context(f.env, await signedRequest(f,
      { ...TARGET, collection: OTHER_COLLECTION, rkey: 'two' }, { proof })));
    expect(replay.status).toBe(400);
    expect((await replay.json() as { error: string }).error).toBe('InvalidToken');
    assertPrivate(replay);
    const second = await GET(context(f.env, await signedRequest(f, { ...TARGET, collection: OTHER_COLLECTION, rkey: 'two' })));
    expect(second.status).toBe(200);
    expect((await second.json() as { value: unknown }).value).toEqual({ $type: OTHER_COLLECTION, text: 'also private' });
    const missing = await GET(context(f.env, await signedRequest(f, { ...TARGET, rkey: 'missing' })));
    expect(missing.status).toBe(400);
    expect((await missing.json() as { error: string }).error).toBe('RecordNotFound');
    assertPrivate(missing);
  });

  it('validates the exact query, header limits and unsupported MAC requests before admission', async () => {
    const f = await authorizedReadFixture();
    const valid = await signedRequest(f);
    const proof = valid.headers.get('dpop') ?? '';
    const query = new URLSearchParams(TARGET).toString();
    for (const candidate of [`${query}&rkey=two`, `${query}&unknown=1`, query.replace(/&rkey=[^&]*/, ''),
      `${query}&space=at%3A%2F%2Fdid%3Aexample%3Aother`, `space=${'x'.repeat(17_000)}`]) {
      const response = await GET(context(f.env, await signedRequest(f, TARGET, { query: candidate, proof })));
      expect(response.status).toBe(400);
      assertPrivate(response);
    }
    for (const signature of ['', 'other=?1', 'invalid', 'sig1=("@method");keyid="example"']) {
      for (const rkey of ['one', 'missing']) {
        const response = await GET(context(f.env, await signedRequest(f, { ...TARGET, rkey }, {
          proof, headers: { 'accept-signature': signature },
        })));
        expect(response.status).toBe(400);
        expect((await response.json() as { error: string }).error).toBe('InvalidSpaceMac');
        assertPrivate(response);
      }
    }
    const largeAuth = new Request(`${PATH}?${query}`, { headers: { authorization: `DPoP ${'a'.repeat(65_536)}` } });
    const largeProof = new Request(`${PATH}?${query}`, { headers: { authorization: 'DPoP token', dpop: 'x'.repeat(16_385) } });
    for (const request of [largeAuth, largeProof]) expect((await GET(context(f.env, request))).status).toBe(400);
    const allowed = await GET(context(f.env, await signedRequest(f, TARGET, { proof })));
    expect(allowed.status).toBe(200);
  });

  it('rejects legacy bearer, app-password and cross-repo access and challenges malformed proofs', async () => {
    const f = await authorizedReadFixture();
    for (const scope of [AuthScope.Access, AuthScope.AppPass, AuthScope.AppPassPrivileged]) {
      const token = await issueSessionTokens(f.env, DID, { accessScope: scope });
      const request = new Request(`${PATH}?${new URLSearchParams(TARGET)}`, { headers: { authorization: `Bearer ${token.accessJwt}` } });
      const response = await GET(context(f.env, request));
      expect(response.status).toBe(401);
      expect(response.headers.get('www-authenticate')).toBe('DPoP');
      expect(response.headers.get('access-control-expose-headers')?.toLowerCase()).toContain('www-authenticate');
      assertPrivate(response);
    }
    const crossRepo = await GET(context(f.env, await signedRequest(f, { ...TARGET, repo: 'did:example:other' })));
    expect(crossRepo.status).toBe(400);
    expect((await crossRepo.json() as { error: string }).error).toBe('RepoNotFound');
    const malformed = new Request(`${PATH}?${new URLSearchParams(TARGET)}`, {
      headers: { authorization: `DPoP ${f.tokens.accessJwt}`, dpop: 'bad.proof.value' },
    });
    const challenged = await GET(context(f.env, malformed));
    expect(challenged.status).toBe(401);
    expect(challenged.headers.get('dpop-nonce')).toBeTruthy();
    expect(challenged.headers.get('access-control-expose-headers')?.toLowerCase()).toContain('dpop-nonce');
    expect(challenged.headers.get('access-control-expose-headers')?.toLowerCase()).toContain('www-authenticate');
    assertPrivate(challenged);
    expect(HEAD().status).toBe(405);
    expect(ALL().status).toBe(405);
    assertPrivate(HEAD());
  });

  it('does not infer a Space grant from ordinary OAuth scope', async () => {
    const f = await authorizedReadFixture();
    const key = await makeDpopKey();
    const session = crypto.randomUUID(), jti = crypto.randomUUID(), clientId = 'https://client.example/metadata';
    const token = await issueSessionTokens(f.env, DID, {
      clientId, dpopJkt: key.jkt, oauthSessionId: session, accessJti: jti, accessScope: 'atproto transition:generic',
    });
    await createOAuthSession(f.env, { id: session, did: DID, clientId, clientAuthMethod: 'none', dpopJkt: key.jkt,
      scope: 'atproto transition:generic', currentRefreshTokenId: token.refreshPayload.jti,
      accessJti: jti, expiresAt: token.refreshExpiry });
    const proof = await signResourceDpop(f.env, key, 'GET', PATH, token.accessJwt);
    const response = await GET(context(f.env, await signedRequest(f, TARGET, { token: token.accessJwt, proof })));
    expect(response.status).toBe(403);
    expect((await response.json() as { error: string }).error).toBe('ScopeMissingError');
    assertPrivate(response);
  });

  it('binds completion to the same request and database and consumes it once', async () => {
    const f = await authorizedReadFixture();
    for (const variant of ['valid', 'request', 'database'] as const) {
      const { principal, request } = await f.principal();
      const result = await readAuthorizedSpaceRecord(f.env, principal, request, SPACE, DID, COLLECTION, 'one');
      if (result.tag !== 'found') throw new Error('Expected a record');
      const database = variant === 'database' ? new Proxy(f.env.ALTERAN_DB, {}) : f.env.ALTERAN_DB;
      const forwarded = variant === 'request' ? request.clone() : request;
      expect(await result.complete(forwarded, database)).toBe(variant === 'valid');
      expect(await result.complete(request, f.env.ALTERAN_DB)).toBe(false);
    }
  });

  it('withholds both found and absent records when revocation wins after serialization', async () => {
    for (const rkey of ['one', 'missing']) {
      const f = await authorizedReadFixture();
      const watched = interceptCompletion(f.env, { beforeSample: async () => {
        await f.env.ALTERAN_DB.prepare('UPDATE oauth_session SET revoked_at = unixepoch() WHERE id = ?').bind(f.sessionId).run();
      } });
      const response = await GET(context(watched, await signedRequest(f, { ...TARGET, rkey })));
      expect(response.status).toBe(401);
      expect(await response.text()).not.toContain('private');
      assertPrivate(response);
    }
  });

  it('withholds found and absent records if revocation wins after the completion sample', async () => {
    for (const rkey of ['one', 'missing']) {
      const f = await authorizedReadFixture();
      const watched = interceptCompletion(f.env, { afterSample: async () => {
        await f.env.ALTERAN_DB.prepare('UPDATE oauth_session SET revoked_at = unixepoch() WHERE id = ?').bind(f.sessionId).run();
      } });
      const response = await GET(context(watched, await signedRequest(f, { ...TARGET, rkey })));
      expect(response.status).toBe(401);
      expect(await response.text()).not.toContain('"text":"private"');
    }
  });

  it('withholds data on tombstone, D1 expiry, cancellation and database faults after serialization', async () => {
    for (const change of ['delete', 'clock', 'cancel', 'fault', 'missing', 'rotate'] as const) {
      const f = await authorizedReadFixture();
      const controller = new AbortController();
      const expiry = Math.floor(Date.now() / 1000) + 60;
      if (change === 'clock') await f.env.ALTERAN_DB.prepare('UPDATE oauth_session SET expires_at = ? WHERE id = ?')
        .bind(expiry, f.sessionId).run();
      const watched = interceptCompletion(f.env, {
        beforeSample: async () => {
          if (change === 'delete') expect((await beginPersonalSpaceDeletion(f.env, SPACE, crypto.randomUUID())).tag).toBe('started');
          if (change === 'clock') await f.env.ALTERAN_DB.prepare('UPDATE oauth_replay_clock SET seconds = ? WHERE id = 1').bind(expiry).run();
          if (change === 'cancel') controller.abort();
          if (change === 'rotate') await f.env.ALTERAN_DB.prepare('UPDATE oauth_session SET access_jti = ? WHERE id = ?')
            .bind('rotated-jti', f.sessionId).run();
        },
        failState: change === 'fault',
        missingState: change === 'missing',
      });
      const response = await GET(context(watched, await signedRequest(f, TARGET, { signal: controller.signal })));
      expect(response.status).toBe(change === 'fault' ? 500 : 401);
      const body = await response.text();
      expect(body).not.toContain('private test failure');
      expect(body).not.toContain('"text":"private"');
      assertPrivate(response);
      if (change === 'clock') {
        const clock = await f.env.ALTERAN_DB.prepare('SELECT seconds FROM oauth_replay_clock WHERE id = 1').first<{ seconds: number }>();
        expect(clock?.seconds).toBeGreaterThanOrEqual(expiry);
      }
    }
  });

  it('commits a clock advance made during the final sample even when it denies the response', async () => {
    const f = await authorizedReadFixture();
    const expiry = Math.floor(Date.now() / 1000) + 60;
    await f.env.ALTERAN_DB.prepare('UPDATE oauth_session SET expires_at = ? WHERE id = ?').bind(expiry, f.sessionId).run();
    const watched = interceptCompletion(f.env, { beforeSample: async () => {
      await f.env.ALTERAN_DB.exec(`CREATE TRIGGER test_completion_clock AFTER UPDATE ON oauth_replay_clock
        WHEN NEW.seconds < ${expiry} BEGIN UPDATE oauth_replay_clock SET seconds = ${expiry} WHERE id = 1; END`.replaceAll('\n', ' '));
    } });
    const response = await GET(context(watched, await signedRequest(f)));
    expect(response.status).toBe(401);
    const clock = await f.env.ALTERAN_DB.prepare('SELECT seconds FROM oauth_replay_clock WHERE id = 1').first<{ seconds: number }>();
    expect(clock?.seconds).toBeGreaterThanOrEqual(expiry);
    expect(await response.text()).not.toContain('"text":"private"');
  });

  it('denies when D1 time reaches session expiry before the completion sample while Worker time lags', async () => {
    const f = await authorizedReadFixture();
    const request = await signedRequest(f);
    const realNow = Date.now;
    const frozen = realNow();
    const expiry = Math.floor(frozen / 1000) + 3;
    await f.env.ALTERAN_DB.prepare('UPDATE oauth_session SET expires_at = ? WHERE id = ?').bind(expiry, f.sessionId).run();
    const watched = interceptCompletion(f.env, { beforeSample: async () => {
      while (Math.floor(realNow() / 1000) < expiry) await new Promise((resolve) => setTimeout(resolve, 20));
    } });
    Date.now = () => frozen;
    try {
      const response = await GET(context(watched, request));
      expect(response.status).toBe(401);
      const clock = await f.env.ALTERAN_DB.prepare('SELECT seconds FROM oauth_replay_clock WHERE id = 1').first<{ seconds: number }>();
      expect(clock?.seconds).toBeGreaterThanOrEqual(expiry);
      expect(await response.text()).not.toContain('"text":"private"');
    } finally {
      Date.now = realNow;
    }
  });

  it('does not combine an active account and a live clock from different D1 moments', async () => {
    const f = await authorizedReadFixture();
    const request = await signedRequest(f);
    const realNow = Date.now;
    const frozen = realNow();
    const expiry = Math.floor(frozen / 1000) + 3;
    await f.env.ALTERAN_DB.prepare('UPDATE oauth_session SET expires_at = ? WHERE id = ?').bind(expiry, f.sessionId).run();
    const watched = interceptCompletion(f.env, {
      beforeSample: () => setAccountState(f.env, DID, { tag: 'deactivated' }),
      afterSample: async () => {
        while (Math.floor(realNow() / 1000) < expiry) await new Promise((resolve) => setTimeout(resolve, 20));
        await setAccountState(f.env, DID, { tag: 'active' });
      },
    });
    Date.now = () => frozen;
    try {
      const response = await GET(context(watched, request));
      expect(response.status).toBe(401);
      expect(await response.text()).not.toContain('"text":"private"');
    } finally {
      Date.now = realNow;
    }
  });

  it('uses the committed completion decision when its readback is delayed past D1 expiry', async () => {
    const f = await authorizedReadFixture();
    const request = await signedRequest(f);
    const realNow = Date.now;
    const frozen = realNow();
    const expiry = Math.floor(frozen / 1000) + 3;
    await f.env.ALTERAN_DB.prepare('UPDATE oauth_session SET expires_at = ? WHERE id = ?').bind(expiry, f.sessionId).run();
    const watched = interceptCompletion(f.env, { afterSample: async () => {
      while (Math.floor(realNow() / 1000) < expiry) await new Promise((resolve) => setTimeout(resolve, 20));
    } });
    Date.now = () => frozen;
    try {
      const response = await GET(context(watched, request));
      expect(response.status).toBe(200);
      expect((await response.json() as { value: unknown }).value).toEqual({ $type: COLLECTION, text: 'private' });
    } finally {
      Date.now = realNow;
    }
    const subsequent = await GET(context(f.env, await signedRequest(f)));
    expect(subsequent.status).toBe(400);
    expect((await subsequent.json() as { error: string }).error).toBe('InvalidToken');
  });

  it('does not release bytes from an epoch replaced before completion', async () => {
    const f = await authorizedReadFixture();
    const watched = interceptCompletion(f.env, { beforeSample: async () => {
      for (const trigger of ['space_lifecycle_epoch_update', 'space_epoch_fence_insert', 'space_lifecycle_epoch_insert',
        'space_epoch_owner_state', 'space_epoch_owner_insert', 'space_repo_owner_update',
        'space_repo_fence_update', 'space_lifecycle_repo_update']) {
        await f.env.ALTERAN_DB.exec(`DROP TRIGGER ${trigger}`);
      }
      await f.env.ALTERAN_DB.prepare("UPDATE space_epoch SET state = 'retired' WHERE space_ref = ? AND repo_did = ?")
        .bind(SPACE, DID).run();
      await f.env.ALTERAN_DB.prepare("INSERT INTO space_epoch (id, space_ref, repo_did, state, created_at) VALUES (?, ?, ?, 'active', unixepoch())")
        .bind('replacement-epoch', SPACE, DID).run();
      await f.env.ALTERAN_DB.prepare('UPDATE space_repo SET active_epoch_id = ? WHERE space_ref = ? AND repo_did = ?')
        .bind('replacement-epoch', SPACE, DID).run();
    } });
    const response = await GET(context(watched, await signedRequest(f)));
    expect(response.status).toBe(401);
    expect(await response.text()).not.toContain('"text":"private"');
  });

  it('denies if a clock trigger replaces the selected epoch before the read transaction finishes', async () => {
    for (const rkey of ['one', 'missing']) {
      const f = await authorizedReadFixture();
      const { principal, request } = await f.principal({ ...TARGET, rkey });
      for (const trigger of ['space_lifecycle_epoch_update', 'space_epoch_fence_insert', 'space_lifecycle_epoch_insert',
        'space_epoch_owner_state', 'space_epoch_owner_insert', 'space_repo_owner_update',
        'space_repo_fence_update', 'space_lifecycle_repo_update']) {
        await f.env.ALTERAN_DB.exec(`DROP TRIGGER ${trigger}`);
      }
      await f.env.ALTERAN_DB.exec(`CREATE TRIGGER test_epoch_swap AFTER UPDATE ON oauth_replay_clock
        WHEN OLD.nonce = NEW.nonce BEGIN
          UPDATE space_epoch SET state = 'retired' WHERE space_ref = '${SPACE}' AND repo_did = '${DID}';
          INSERT INTO space_epoch (id, space_ref, repo_did, state, created_at)
            VALUES ('replacement-epoch', '${SPACE}', '${DID}', 'active', unixepoch());
          UPDATE space_repo SET active_epoch_id = 'replacement-epoch' WHERE space_ref = '${SPACE}' AND repo_did = '${DID}';
        END`.replaceAll('\n', ' '));
      const result = await readAuthorizedSpaceRecord(f.env, principal, request, SPACE, DID, COLLECTION, rkey);
      expect(result.tag).toBe('unauthorized');
    }
  });

  it('rejects incomplete or oversized selected-epoch results', async () => {
    const f = await authorizedReadFixture();
    for (const change of ['sentinel', 'record', 'oversized'] as const) {
      const watched = interceptRead(f.env, { after: (results) => {
        const rows = (results[2] as { results: { sentinel: number; epoch_id: unknown }[] }).results;
        const final = (results[5] as { results: { epoch_id: unknown }[] }).results[0];
        const sentinel = rows.find((row) => row.sentinel === 1);
        const record = rows.find((row) => row.sentinel === 0);
        if (!sentinel || !record) throw new Error('Missing test rows');
        if (change === 'sentinel') sentinel.epoch_id = 7;
        if (change === 'record') record.epoch_id = null;
        if (change === 'oversized') sentinel.epoch_id = record.epoch_id = final.epoch_id = 'x'.repeat(129);
      } });
      const { principal, request } = await f.principal(TARGET, watched.env);
      watched.arm();
      expect((await readAuthorizedSpaceRecord(watched.env, principal, request, SPACE, DID, COLLECTION, 'one')).tag).toBe('unauthorized');
    }
  });

  it('checks the Worker clock after the final D1 await', async () => {
    const f = await authorizedReadFixture();
    const realNow = Date.now;
    const expiry = f.tokens.accessPayload.exp;
    const watched = interceptCompletion(f.env, { afterState: () => { Date.now = () => expiry * 1000; } });
    try {
      const response = await GET(context(watched, await signedRequest(f)));
      expect(response.status).toBe(401);
      expect(await response.text()).not.toContain('"text":"private"');
    } finally {
      Date.now = realNow;
    }
  });
});
