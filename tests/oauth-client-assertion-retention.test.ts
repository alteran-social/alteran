import { expect } from '@std/expect';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { describe, it } from './helpers/bdd';
import { makeEnv } from './helpers/env';
import { advanceReplayClock, afterReplayBatch } from './helpers/oauth-clock';
import { getSecret, setSecret } from '../src/db/account';
import { cleanupExpiredOAuthReplaySecrets } from '../src/db/oauth-replay';
import { verifyClientAssertion } from '../src/lib/oauth/clients';
import { jwkThumbprint } from '../src/lib/oauth/dpop';

const CLIENT = 'https://client.example/metadata';
const ISSUER = 'https://pds.example';

describe('confidential client assertion retention', () => {
  it('rejects reuse of an assertion with a fractional expiration', async () => {
    const env = await makeEnv();
    const pair = await generateKeyPair('ES256');
    const jwk = { ...await exportJWK(pair.publicKey), kid: 'client-key' };
    const originalNow = Date.now;
    const now = Math.floor(originalNow() / 1000);
    const jwt = await new SignJWT({
      iss: CLIENT, sub: CLIENT, aud: ISSUER, iat: now, exp: now + 10.5, jti: crypto.randomUUID(),
    }).setProtectedHeader({ alg: 'ES256', kid: 'client-key' }).sign(pair.privateKey);
    try {
      Date.now = () => (now + 10) * 1000;
      await advanceReplayClock(env, now + 10);
      expect(await verifyClientAssertion(env, CLIENT, ISSUER, jwt, { keys: [jwk] }))
        .toEqual({ keyId: await jwkThumbprint(jwk) });
      expect(await verifyClientAssertion(env, CLIENT, ISSUER, jwt, { keys: [jwk] })).toBeNull();
    } finally {
      Date.now = originalNow;
    }
  });

  it('rejects assertions whose expiration or issue-time window lapses during marker insertion', async () => {
    const env = await makeEnv();
    const pair = await generateKeyPair('ES256');
    const jwk = { ...await exportJWK(pair.publicKey), kid: 'client-key' };
    const originalNow = Date.now;
    const now = Math.floor(originalNow() / 1000);
    let clock = now;
    const delayed = afterReplayBatch(env, () => { clock = now + 1; });
    try {
      Date.now = () => clock * 1000;
      for (const times of [
        { iat: now, exp: now + 0.5 },
        { iat: now - 300, exp: now + 60 },
      ]) {
        clock = now;
        const jwt = await new SignJWT({
          iss: CLIENT, sub: CLIENT, aud: ISSUER, ...times, jti: crypto.randomUUID(),
        }).setProtectedHeader({ alg: 'ES256', kid: 'client-key' }).sign(pair.privateKey);
        expect(await verifyClientAssertion(delayed, CLIENT, ISSUER, jwt, { keys: [jwk] })).toBeNull();
        expect(clock).toBe(now + 1);
      }
    } finally {
      Date.now = originalNow;
    }
  });

  it('retains legacy fractional-expiration markers until their assertions expire', async () => {
    const env = await makeEnv();
    const pair = await generateKeyPair('ES256');
    const jwk = { ...await exportJWK(pair.publicKey), kid: 'client-key' };
    const originalNow = Date.now;
    const now = Math.floor(originalNow() / 1000);
    const jti = crypto.randomUUID();
    const marker = `oauth:client-assertion:jti:${CLIENT}:${jti}`;
    const jwt = await new SignJWT({
      iss: CLIENT, sub: CLIENT, aud: ISSUER, iat: now, exp: now + 10.5, jti,
    }).setProtectedHeader({ alg: 'ES256', kid: 'client-key' }).sign(pair.privateKey);
    await setSecret(env, marker, JSON.stringify({ exp: now + 10.5 }));
    try {
      Date.now = () => (now + 10) * 1000;
      await advanceReplayClock(env, now + 10);
      expect(await verifyClientAssertion(env, CLIENT, ISSUER, jwt, { keys: [jwk] })).toBeNull();
      expect(await getSecret(env, marker)).not.toBeNull();
      await advanceReplayClock(env, now + 11);
      await cleanupExpiredOAuthReplaySecrets(env);
      expect(await getSecret(env, marker)).toBeNull();
    } finally {
      Date.now = originalNow;
    }
  });

  it('keeps malformed replay rows while cleaning independently valid expired rows', async () => {
    const env = await makeEnv();
    const now = Math.floor(Date.now() / 1000);
    const unknownIat = 'oauth:dpop:jti:authz:unknown-iat';
    const missingIat = 'oauth:dpop:jti:authz:missing-iat';
    const unknownExp = 'oauth:client-assertion:jti:unknown-exp';
    const malformed = 'oauth:dpop:jti:authz:malformed';
    const expired = 'oauth:client-assertion:jti:valid-expired';
    await setSecret(env, unknownIat, JSON.stringify({ iat: 'unknown', exp: 1 }));
    await setSecret(env, missingIat, JSON.stringify({ exp: 1 }));
    await setSecret(env, unknownExp, JSON.stringify({ exp: 'unknown' }));
    await setSecret(env, malformed, '{');
    await setSecret(env, expired, JSON.stringify({ exp: 1 }));
    await cleanupExpiredOAuthReplaySecrets(env);
    for (const key of [unknownIat, missingIat, unknownExp, malformed]) {
      expect(await getSecret(env, key)).not.toBeNull();
    }
    expect(await getSecret(env, expired)).toBeNull();
  });
});
