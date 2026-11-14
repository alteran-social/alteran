import type { APIContext } from 'astro';
import { expect } from '@std/expect';
import { describe, it } from './helpers/bdd';
import { makeEnv } from './helpers/env';
import { makeDpopKey, signDpopProof } from './helpers/oauth';
import { createOAuthSession } from './helpers/oauth-store';
import { getSecret, setSecret, storeRefreshToken } from '../src/db/account';
import { issueSessionTokens } from '../src/lib/session-tokens';
import { issueAuthorizationCode } from '../src/lib/oauth/issue-code';
import { consumeConsent, loadParSnapshot, saveConsent, savePar, type ParRecord } from '../src/lib/oauth/store';
import { POST as parPost } from '../src/pages/oauth/par';
import { POST as revokePost } from '../src/pages/oauth/revoke';
import { POST as consentPost } from '../src/pages/oauth/consent';

function record(state: string): ParRecord {
  const now = Math.floor(Date.now() / 1000);
  return { client_id: 'http://localhost', redirect_uri: 'http://127.0.0.1:1234/', code_challenge: 'challenge',
    code_challenge_method: 'S256', scope: 'atproto', state, dpopJkt: 'jkt', clientAuthMethod: 'none',
    createdAt: now, expiresAt: now + 300 };
}

describe('bounded OAuth form and snapshot storage', () => {
  it('rejects oversized stored PAR and consent without transferring their values', async () => {
    const env = await makeEnv();
    await setSecret(env, 'oauth:par:oversized', 'x'.repeat(200_000));
    await setSecret(env, 'oauth:consent:oversized', 'x'.repeat(600_000));
    let largest = 0;
    const database = env.ALTERAN_DB;
    const measured = { ...env, ALTERAN_DB: new Proxy(database, {
      get(target, property) {
        if (property === 'prepare') return (sql: string) => {
          const statement = target.prepare(sql);
          return new Proxy(statement, {
            get(prepared, member) {
              if (member === 'bind') return (...args: unknown[]) => {
                const bound = prepared.bind(...args);
                return new Proxy(bound, {
                  get(query, operation) {
                    if (operation === 'first') return async () => {
                      const result = await query.first();
                      largest = Math.max(largest, JSON.stringify(result)?.length ?? 0);
                      return result;
                    };
                    const value = Reflect.get(query, operation, query);
                    return typeof value === 'function' ? value.bind(query) : value;
                  },
                });
              };
              const value = Reflect.get(prepared, member, prepared);
              return typeof value === 'function' ? value.bind(prepared) : value;
            },
          });
        };
        const value = Reflect.get(target, property, target);
        return typeof value === 'function' ? value.bind(target) : value;
      },
    }) };
    expect(await loadParSnapshot(measured, 'oversized')).toBeNull();
    expect(await consumeConsent(measured, 'oversized', 'csrf')).toBeNull();
    expect(largest).toBeLessThan(1_000);
  });

  it('round-trips escaped PAR data inside bounded consent', async () => {
    const env = await makeEnv();
    await savePar(env, 'bounded', record('\\'.repeat(16_000)));
    const snapshot = await loadParSnapshot(env, 'bounded');
    if (!snapshot) throw new Error('Missing PAR');
    await saveConsent(env, 'bounded', 'csrf', Math.floor(Date.now() / 1000) + 300, snapshot.value);
    expect((await consumeConsent(env, 'bounded', 'csrf'))?.parValue).toBe(snapshot.value);
  });

  it('rejects a PAR whose escaped snapshot exceeds its storage limit before spending DPoP', async () => {
    const env = await makeEnv();
    const key = await makeDpopKey();
    const url = 'https://pds.example/oauth/par';
    const jti = crypto.randomUUID();
    const proof = await signDpopProof({ key, method: 'POST', url, jti });
    const form = new URLSearchParams({ client_id: 'http://localhost', response_type: 'code',
      redirect_uri: 'http://127.0.0.1:1234/', scope: 'atproto', state: '\\'.repeat(40_000),
      code_challenge: 'challenge', code_challenge_method: 'S256' });
    const response = await parPost({ locals: { env }, request: new Request(url, { method: 'POST',
      headers: { DPoP: proof }, body: form }) } as unknown as APIContext);
    expect(response.status).toBe(400);
    expect((await response.json() as { error_description?: string }).error_description).toContain('storage limit');
    expect(await getSecret(env, `oauth:dpop:jti:authz:${jti}`)).toBeNull();
  });

  it('does not issue a code that would exceed the code snapshot limit', async () => {
    const env = await makeEnv();
    await savePar(env, 'bounded', record('state'));
    const snapshot = await loadParSnapshot(env, 'bounded');
    if (!snapshot) throw new Error('Missing PAR');
    const now = Math.floor(Date.now() / 1000);
    const code = await issueAuthorizationCode(env, 'bounded', snapshot,
      { id: 'bounded', csrf: 'csrf', createdAt: now, expiresAt: now + 300, parValue: snapshot.value },
      `did:example:${'x'.repeat(140_000)}`);
    expect(code).toBeNull();
    expect((await loadParSnapshot(env, 'bounded'))?.value).toBe(snapshot.value);
  });

  it('bounds PAR, revoke and consent request streams without Content-Length', async () => {
    const env = await makeEnv();
    const key = await makeDpopKey();
    for (const [path, handler] of [['par', parPost], ['revoke', revokePost], ['consent', consentPost]] as const) {
      const url = `https://pds.example/oauth/${path}`;
      const jti = crypto.randomUUID();
      const proof = await signDpopProof({ key, method: 'POST', url, jti });
      const stream = new ReadableStream<Uint8Array>({ start(controller) {
        controller.enqueue(new Uint8Array(600_000));
        controller.enqueue(new Uint8Array(600_000));
        controller.close();
      } });
      const request = new Request(url, { method: 'POST', headers: { DPoP: proof, Origin: 'https://pds.example' },
        body: stream, duplex: 'half' } as RequestInit);
      expect((await handler({ locals: { env }, request } as unknown as APIContext)).status).toBe(400);
      expect(await getSecret(env, `oauth:dpop:jti:authz:${jti}`)).toBeNull();
    }
  });

  it('does not transfer an oversized session while processing either revocation token type', async () => {
    const env = await makeEnv({ SESSION_JWT_SECRET: 'bounded-revoke-test-secret' });
    const key = await makeDpopKey();
    const did = 'did:example:test';
    const client = 'https://client.example/metadata';
    const session = crypto.randomUUID();
    const accessJti = crypto.randomUUID();
    const tokens = await issueSessionTokens(env, did, { accessScope: 'atproto', clientId: client,
      dpopJkt: key.jkt, oauthSessionId: session, accessJti });
    await createOAuthSession(env, { id: session, did, clientId: client, clientAuthMethod: 'none', dpopJkt: key.jkt,
      scope: 'atproto', currentRefreshTokenId: tokens.refreshPayload.jti, accessJti, expiresAt: tokens.refreshExpiry });
    await storeRefreshToken(env, { id: tokens.refreshPayload.jti, did, expiresAt: tokens.refreshExpiry, tokenKind: 'oauth',
      oauthSessionId: session, clientId: client, clientAuthMethod: 'none', dpopJkt: key.jkt, oauthScope: 'atproto', accessJti });
    await env.ALTERAN_DB.prepare('UPDATE oauth_session SET scope = ? WHERE id = ?').bind('x'.repeat(400_000), session).run();
    let largest = 0;
    let checked = 0;
    const database = env.ALTERAN_DB;
    const measured = { ...env, ALTERAN_DB: new Proxy(database, {
      get(target, property) {
        if (property === 'prepare') return (sql: string) => {
          const statement = target.prepare(sql);
          if (!sql.includes('FROM refresh_token r JOIN oauth_session') && !sql.includes('FROM oauth_session s')) return statement;
          return new Proxy(statement, { get(prepared, member) {
            if (member === 'bind') return (...args: unknown[]) => {
              const bound = prepared.bind(...args);
              return new Proxy(bound, { get(query, operation) {
                if (operation === 'first') return async () => {
                  const result = await query.first();
                  checked++;
                  largest = Math.max(largest, JSON.stringify(result)?.length ?? 0);
                  return result;
                };
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
      },
    }) };
    for (const token of [tokens.refreshJwt, tokens.accessJwt]) {
      const url = 'https://pds.example/oauth/revoke';
      const proof = await signDpopProof({ key, method: 'POST', url });
      const request = new Request(url, { method: 'POST', headers: { DPoP: proof },
        body: new URLSearchParams({ token, client_id: client }) });
      expect((await revokePost({ locals: { env: measured }, request } as unknown as APIContext)).status).toBe(200);
    }
    expect(checked).toBe(2);
    expect(largest).toBeLessThan(1_000);
  });
});
