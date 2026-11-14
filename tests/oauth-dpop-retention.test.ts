import { createOAuthSession } from './helpers/oauth-store';
import { expect } from '@std/expect';
import { SignJWT, type JWK } from 'jose';
import { describe, it } from './helpers/bdd';
import { makeEnv } from './helpers/env';
import { makeDpopKey } from './helpers/oauth';
import { advanceReplayClock, afterReplayBatch } from './helpers/oauth-clock';
import { getSecret, setSecret } from '../src/db/account';
import { cleanupExpiredOAuthReplaySecrets } from '../src/db/oauth-replay';
import { verifyDpop, sha256b64url } from '../src/lib/oauth/dpop';
import { dpopResourceUnauthorized, verifyResourceRequestHybrid } from '../src/lib/oauth/resource';
import { issueSessionTokens } from '../src/lib/session-tokens';

const URL = 'https://pds.example/oauth/token';

describe('DPoP proof retention', () => {
  it('uses a query-free target on authorization requests and still rejects replay', async () => {
    const env = await makeEnv();
    const key = await makeDpopKey();
    const now = Math.floor(Date.now() / 1000);
    const proof = await new SignJWT({ htm: 'POST', htu: URL, iat: now, jti: crypto.randomUUID() })
      .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: key.jwk as JWK })
      .sign(key.privateKey);
    const request = (query: string) => new Request(`${URL}?${query}`, {
      method: 'POST', headers: { dpop: proof },
    });
    await verifyDpop(env, request('first=1'), { requireNonce: false });
    await expect(verifyDpop(env, request('second=2'), { requireNonce: false }))
      .rejects.toThrow('DPoP proof replayed');
  });

  it('retains signed authorization proofs until the last accepted second', async () => {
    const env = await makeEnv();
    const key = await makeDpopKey();
    const originalNow = Date.now;
    const now = Math.floor(originalNow() / 1000);
    const jti = crypto.randomUUID();
    const proof = await new SignJWT({ htm: 'POST', htu: URL, iat: now + 30, jti })
      .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: key.jwk as JWK })
      .sign(key.privateKey);
    const request = () => new Request(URL, { method: 'POST', headers: { dpop: proof } });
    try {
      Date.now = () => now * 1000;
      await verifyDpop(env, request(), { requireNonce: false });
      await expect(verifyDpop(env, request(), { requireNonce: false })).rejects
        .toThrow('DPoP proof replayed');

      Date.now = () => (now + 300) * 1000;
      await advanceReplayClock(env, now + 300);
      await expect(verifyDpop(env, request(), { requireNonce: false })).rejects
        .toThrow('DPoP proof replayed');
      Date.now = () => (now + 330) * 1000;
      await advanceReplayClock(env, now + 330);
      await expect(verifyDpop(env, request(), { requireNonce: false })).rejects
        .toThrow('DPoP proof replayed');

      Date.now = () => (now + 331) * 1000;
      await expect(verifyDpop(env, request(), { requireNonce: false })).rejects
        .toThrow('DPoP iat too old');
      await advanceReplayClock(env, now + 331);
      await cleanupExpiredOAuthReplaySecrets(env);
      expect(await getSecret(env, `oauth:dpop:jti:authz:${jti}`)).not.toBeNull();
      await advanceReplayClock(env, now + 332);
      await cleanupExpiredOAuthReplaySecrets(env);
      expect(await getSecret(env, `oauth:dpop:jti:authz:${jti}`)).toBeNull();
    } finally {
      Date.now = originalNow;
    }
  });

  it('also retains fractional timestamps through their last valid second', async () => {
    const env = await makeEnv();
    const key = await makeDpopKey();
    const originalNow = Date.now;
    const now = Math.floor(originalNow() / 1000);
    const proof = await new SignJWT({ htm: 'POST', htu: URL, iat: now + 29.5, jti: crypto.randomUUID() })
      .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: key.jwk as JWK })
      .sign(key.privateKey);
    const request = () => new Request(URL, { method: 'POST', headers: { dpop: proof } });
    try {
      Date.now = () => now * 1000;
      await verifyDpop(env, request(), { requireNonce: false });
      Date.now = () => (now + 329) * 1000;
      await advanceReplayClock(env, now + 329);
      await expect(verifyDpop(env, request(), { requireNonce: false })).rejects
        .toThrow('DPoP proof replayed');
      Date.now = () => (now + 330) * 1000;
      await expect(verifyDpop(env, request(), { requireNonce: false })).rejects
        .toThrow('DPoP iat too old');
    } finally {
      Date.now = originalNow;
    }
  });

  it('retains a legacy marker whose original expiry is shorter than its proof window', async () => {
    const env = await makeEnv();
    const key = await makeDpopKey();
    const originalNow = Date.now;
    const now = Math.floor(originalNow() / 1000);
    const jti = crypto.randomUUID();
    const marker = `oauth:dpop:jti:authz:${jti}`;
    const proof = await new SignJWT({ htm: 'POST', htu: URL, iat: now + 30, jti })
      .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: key.jwk as JWK })
      .sign(key.privateKey);
    await setSecret(env, marker, JSON.stringify({ iat: now + 30, exp: now + 300 }));
    const request = () => new Request(URL, { method: 'POST', headers: { dpop: proof } });
    try {
      Date.now = () => (now + 300) * 1000;
      await advanceReplayClock(env, now + 300);
      await expect(verifyDpop(env, request(), { requireNonce: false })).rejects
        .toThrow('DPoP proof replayed');
      Date.now = () => (now + 330) * 1000;
      await advanceReplayClock(env, now + 330);
      await expect(verifyDpop(env, request(), { requireNonce: false })).rejects
        .toThrow('DPoP proof replayed');
      await advanceReplayClock(env, now + 331);
      await cleanupExpiredOAuthReplaySecrets(env);
      expect(await getSecret(env, marker)).toBeNull();
    } finally {
      Date.now = originalNow;
    }
  });

  it('rejects a proof that expires while its authorization replay marker is being written', async () => {
    const env = await makeEnv();
    const key = await makeDpopKey();
    const originalNow = Date.now;
    const now = Math.floor(originalNow() / 1000);
    const proof = await new SignJWT({ htm: 'POST', htu: URL, iat: now - 300, jti: crypto.randomUUID() })
      .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: key.jwk as JWK })
      .sign(key.privateKey);
    let clock = now;
    const delayed = afterReplayBatch(env, () => { clock = now + 1; });
    try {
      Date.now = () => clock * 1000;
      await expect(verifyDpop(delayed, new Request(URL, {
        method: 'POST', headers: { dpop: proof },
      }), { requireNonce: false })).rejects.toThrow('DPoP proof expired');
    } finally {
      Date.now = originalNow;
    }
  });

  it('retains resource proofs for the same interval when a nonce remains valid', async () => {
    const env = await makeEnv();
    const key = await makeDpopKey();
    const now = Math.floor(Date.now() / 1000);
    const sessionId = crypto.randomUUID().replace(/-/g, '');
    const accessJti = crypto.randomUUID().replace(/-/g, '');
    const clientId = 'https://client.example/metadata';
    const tokens = await issueSessionTokens(env, 'did:example:test', {
      accessScope: 'atproto', clientId, dpopJkt: key.jkt, oauthSessionId: sessionId, accessJti,
    });
    await createOAuthSession(env, {
      id: sessionId, did: 'did:example:test', clientId, clientAuthMethod: 'none',
      dpopJkt: key.jkt, scope: 'atproto', currentRefreshTokenId: tokens.refreshPayload.jti,
      accessJti, expiresAt: tokens.refreshExpiry,
    });
    const url = 'https://pds.example/xrpc/com.atproto.repo.getRecord';
    const nonce = (await dpopResourceUnauthorized(env)).headers.get('DPoP-Nonce')!;
    const jti = crypto.randomUUID();
    const proof = await new SignJWT({
      htm: 'GET', htu: url, iat: now + 30, jti, nonce, ath: await sha256b64url(tokens.accessJwt),
    }).setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: key.jwk as JWK }).sign(key.privateKey);
    const request = () => new Request(url, { headers: { authorization: `DPoP ${tokens.accessJwt}`, dpop: proof } });
    const originalNow = Date.now;
    try {
      Date.now = () => now * 1000;
      expect((await verifyResourceRequestHybrid(env, request()))?.did).toBe('did:example:test');
      Date.now = () => (now + 300) * 1000;
      await advanceReplayClock(env, now + 300);
      // Keep the nonce stable to test the replay cache independently of nonce rotation.
      await setSecret(env, 'oauth_dpop_nonce_pds', JSON.stringify({ v: nonce, ts: now + 300 }));
      await expect(verifyResourceRequestHybrid(env, request())).rejects.toMatchObject({
        code: 'invalid_token', message: 'DPoP proof replayed',
      });
    } finally {
      Date.now = originalNow;
    }
  });

  it('rejects a resource proof that expires while its replay marker is being written', async () => {
    const env = await makeEnv();
    const key = await makeDpopKey();
    const now = Math.floor(Date.now() / 1000);
    const sessionId = crypto.randomUUID().replace(/-/g, '');
    const accessJti = crypto.randomUUID().replace(/-/g, '');
    const clientId = 'https://client.example/metadata';
    const tokens = await issueSessionTokens(env, 'did:example:test', {
      accessScope: 'atproto', clientId, dpopJkt: key.jkt, oauthSessionId: sessionId, accessJti,
    });
    await createOAuthSession(env, {
      id: sessionId, did: 'did:example:test', clientId, clientAuthMethod: 'none',
      dpopJkt: key.jkt, scope: 'atproto', currentRefreshTokenId: tokens.refreshPayload.jti,
      accessJti, expiresAt: tokens.refreshExpiry,
    });
    const url = 'https://pds.example/xrpc/com.atproto.repo.getRecord';
    const nonce = (await dpopResourceUnauthorized(env)).headers.get('DPoP-Nonce')!;
    const proof = await new SignJWT({
      htm: 'GET', htu: url, iat: now - 300, jti: crypto.randomUUID(), nonce,
      ath: await sha256b64url(tokens.accessJwt),
    }).setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: key.jwk as JWK }).sign(key.privateKey);
    const request = new Request(url, { headers: { authorization: `DPoP ${tokens.accessJwt}`, dpop: proof } });
    const originalNow = Date.now;
    let clock = now;
    const delayed = afterReplayBatch(env, () => { clock = now + 1; });
    try {
      Date.now = () => clock * 1000;
      await expect(verifyResourceRequestHybrid(delayed, request)).rejects.toMatchObject({
        code: 'use_dpop_nonce', message: 'DPoP proof expired',
      });
    } finally {
      Date.now = originalNow;
    }
  });
});
