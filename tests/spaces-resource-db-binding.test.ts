import { expect } from '@std/expect';
import { decodeJwt } from 'jose';
import { describe, it } from './helpers/bdd';
import { authorizedReadFixture, COLLECTION, DID, SPACE } from './helpers/spaces-authorized-read';
import { makeEnv } from './helpers/env';
import { signResourceDpop } from './helpers/oauth';
import { createOAuthSession } from './helpers/oauth-store';
import { issueSessionTokens } from '../src/lib/session-tokens';
import { consumeVerifiedSpacePrincipal, ResourceAuthError, verifyResourceRequest } from '../src/lib/oauth/resource';

const ENDPOINT = 'https://pds.example/xrpc/com.atproto.space.getRecord';
type Fixture = Awaited<ReturnType<typeof authorizedReadFixture>>;
type Environment = Fixture['env'];
type Database = Environment['ALTERAN_DB'];
type Hooks = {
  afterGrant?: () => void;
  afterReplay?: () => void;
  afterStatus?: () => void;
};

function watchDatabase(database: Database, hooks: Hooks = {}): Database {
  return new Proxy(database, { get(target, property) {
    if (property === 'batch') return async (statements: Parameters<Database['batch']>[0]) => {
      const result = await database.batch(statements);
      if (statements.length === 9) hooks.afterReplay?.();
      return result;
    };
    if (property === 'prepare') return (sql: string) => {
      const statement = database.prepare(sql);
      const watchGrant = sql.includes('FROM oauth_space_grant g JOIN oauth_session');
      const watchStatus = /^select\b/i.test(sql.trimStart()) && sql.includes('"account_state"');
      if (!watchGrant && !watchStatus) return statement;
      return new Proxy(statement, { get(prepared, member) {
        if (member === 'bind') return (...values: Parameters<typeof prepared.bind>) => {
          const bound = prepared.bind(...values);
          return new Proxy(bound, { get(query, operation) {
            if ((watchGrant && operation === 'first') || (watchStatus && operation === 'raw')) {
              const method = Reflect.get(query, operation, query);
              return async (...args: unknown[]) => {
                const result = await Reflect.apply(method, query, args);
                if (watchGrant) hooks.afterGrant?.();
                if (watchStatus) hooks.afterStatus?.();
                return result;
              };
            }
            const value = Reflect.get(query, operation, query);
            return typeof value === 'function' ? value.bind(query) : value;
          } });
        };
        const value = Reflect.get(prepared, member, prepared);
        return typeof value === 'function' ? value.bind(prepared) : value;
      } });
    };
    const value = Reflect.get(target, property, target);
    return typeof value === 'function' ? value.bind(target) : value;
  } });
}

function inheritedEnvironment(base: Environment, database: Database): Environment {
  const env = Object.create(base) as Environment;
  Object.defineProperty(env, 'ALTERAN_DB', { value: database, writable: true, configurable: true });
  return env;
}

async function signed(fixture: Fixture, token = fixture.tokens.accessJwt) {
  const proof = await signResourceDpop(fixture.env, fixture.key, 'GET', ENDPOINT, token);
  const query = new URLSearchParams({ space: SPACE, repo: DID, collection: COLLECTION, rkey: 'one' });
  const request = new Request(`${ENDPOINT}?${query}`, {
    headers: { authorization: `DPoP ${token}`, dpop: proof },
  });
  return { request, proof };
}

async function expectDenied(env: Environment, request: Request) {
  let error: unknown;
  try { await verifyResourceRequest(env, request); } catch (cause) { error = cause; }
  expect(error).toBeInstanceOf(ResourceAuthError);
  expect((error as ResourceAuthError).code).toBe('invalid_token');
}

describe('Space resource database binding', () => {
  it('rejects a binding replaced after replay admission', async () => {
    const fixture = await authorizedReadFixture();
    const { request, proof } = await signed(fixture);
    const replacement = watchDatabase(fixture.env.ALTERAN_DB);
    let changed = false;
    let env: Environment;
    const captured = watchDatabase(fixture.env.ALTERAN_DB, { afterReplay: () => {
      changed = true;
      env.ALTERAN_DB = replacement;
    } });
    env = inheritedEnvironment(fixture.env, captured);
    await expectDenied(env, request);
    expect(changed).toBe(true);
    const jti = decodeJwt(proof).jti;
    const stored = await fixture.env.ALTERAN_DB.prepare('SELECT 1 AS present FROM secret WHERE key = ?')
      .bind(`oauth:dpop:jti:resource:${jti}`).first<{ present: number }>();
    expect(stored?.present).toBe(1);
  });

  it('rejects a binding replaced during account status resolution', async () => {
    const fixture = await authorizedReadFixture();
    const { request } = await signed(fixture);
    const replacement = watchDatabase(fixture.env.ALTERAN_DB);
    let changed = false;
    let env: Environment;
    const captured = watchDatabase(fixture.env.ALTERAN_DB, { afterStatus: () => {
      changed = true;
      env.ALTERAN_DB = replacement;
    } });
    env = inheritedEnvironment(fixture.env, captured);
    await expectDenied(env, request);
    expect(changed).toBe(true);
  });

  it('keeps replay admission on the captured binding across a transient swap', async () => {
    const fixture = await authorizedReadFixture();
    const { request } = await signed(fixture);
    let env: Environment;
    let replayBinding = '';
    const replacement = watchDatabase(fixture.env.ALTERAN_DB, { afterReplay: () => {
      replayBinding = 'replacement';
      env.ALTERAN_DB = captured;
    } });
    const captured = watchDatabase(fixture.env.ALTERAN_DB, {
      afterGrant: () => { env.ALTERAN_DB = replacement; },
      afterReplay: () => { replayBinding = 'captured'; env.ALTERAN_DB = captured; },
    });
    env = inheritedEnvironment(fixture.env, captured);
    const auth = await verifyResourceRequest(env, request);
    expect(replayBinding).toBe('captured');
    expect(auth?.spacePrincipal).toBeTruthy();
    expect(consumeVerifiedSpacePrincipal(auth?.spacePrincipal, request, captured)).toBe(true);
  });

  it('stores the replay marker only on the captured D1 across a swap to another database', async () => {
    const fixture = await authorizedReadFixture();
    const other = await makeEnv();
    const { request, proof } = await signed(fixture);
    let env: Environment;
    let swapped = false;
    let replayed = false;
    const captured = watchDatabase(fixture.env.ALTERAN_DB, {
      afterGrant: () => { swapped = true; env.ALTERAN_DB = other.ALTERAN_DB; },
      afterReplay: () => { replayed = true; env.ALTERAN_DB = captured; },
    });
    env = inheritedEnvironment(fixture.env, captured);
    const result = await verifyResourceRequest(env, request);
    expect(swapped).toBe(true);
    expect(replayed).toBe(true);
    expect(consumeVerifiedSpacePrincipal(result?.spacePrincipal, request, captured)).toBe(true);
    const key = `oauth:dpop:jti:resource:${decodeJwt(proof).jti}`;
    const stored = await fixture.env.ALTERAN_DB.prepare('SELECT 1 AS present FROM secret WHERE key = ?').bind(key).first();
    const absent = await other.ALTERAN_DB.prepare('SELECT 1 AS present FROM secret WHERE key = ?').bind(key).first();
    expect(stored).toBeTruthy();
    expect(absent).toBeNull();
  });

  it('accepts stable inherited bindings for Space and ordinary OAuth tokens', async () => {
    const fixture = await authorizedReadFixture();
    const env = inheritedEnvironment(fixture.env, fixture.env.ALTERAN_DB);
    const space = await signed(fixture);
    const auth = await verifyResourceRequest(env, space.request);
    expect(auth?.spacePrincipal).toBeTruthy();
    expect(consumeVerifiedSpacePrincipal(auth?.spacePrincipal, space.request, env.ALTERAN_DB)).toBe(true);
    const sessionId = crypto.randomUUID(), accessJti = crypto.randomUUID();
    const clientId = 'https://client.example/metadata';
    const tokens = await issueSessionTokens(fixture.env, DID, {
      accessScope: 'atproto transition:generic', clientId, dpopJkt: fixture.key.jkt,
      oauthSessionId: sessionId, accessJti,
    });
    await createOAuthSession(fixture.env, {
      id: sessionId, did: DID, clientId, clientAuthMethod: 'none', dpopJkt: fixture.key.jkt,
      scope: 'atproto transition:generic', currentRefreshTokenId: tokens.refreshPayload.jti,
      accessJti, expiresAt: tokens.refreshExpiry,
    });
    const ordinary = await signed(fixture, tokens.accessJwt);
    const result = await verifyResourceRequest(env, ordinary.request);
    expect(result?.authType).toBe('oauth-dpop');
    expect(result?.spacePrincipal).toBeUndefined();
  });

  it('retains the original receiver for a non-enumerable inherited binding', async () => {
    const fixture = await authorizedReadFixture();
    const prototype = Object.create(fixture.env) as Environment;
    let env: Environment;
    Object.defineProperty(prototype, 'PDS_DID', { configurable: true, get() {
      if (this !== env) throw new Error('Unexpected environment receiver');
      return fixture.env.PDS_DID;
    } });
    env = inheritedEnvironment(prototype, fixture.env.ALTERAN_DB);
    const signedRequest = await signed(fixture);
    const auth = await verifyResourceRequest(env, signedRequest.request);
    expect(auth?.spacePrincipal).toBeTruthy();
    expect(consumeVerifiedSpacePrincipal(auth?.spacePrincipal, signedRequest.request, env.ALTERAN_DB)).toBe(true);
  });
});
