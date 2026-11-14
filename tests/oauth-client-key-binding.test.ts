import { expect } from '@std/expect';
import { exportJWK, generateKeyPair, SignJWT, type KeyLike } from 'jose';
import { describe, it } from './helpers/bdd';
import { makeEnv } from './helpers/env';
import { requireSameClientAuth, requireStoredClientAuthentication, validateClientMetadataShape, verifyClientAuthentication } from '../src/lib/oauth/clients';
import { jwkThumbprint } from '../src/lib/oauth/dpop';

const CLIENT = 'https://client.example/metadata';
const ISSUER = 'https://pds.example';
const TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

async function assertion(key: KeyLike, kid?: string) {
  const now = Math.floor(Date.now() / 1000);
  const jwt = await new SignJWT({ iss: CLIENT, sub: CLIENT, aud: ISSUER, iat: now, exp: now + 120, jti: crypto.randomUUID() })
    .setProtectedHeader({ alg: 'ES256', ...(kid === undefined ? {} : { kid }) }).sign(key);
  return new URLSearchParams({ client_assertion_type: TYPE, client_assertion: jwt });
}

function metadata(keys: JsonWebKey[]) {
  return validateClientMetadataShape({
    client_id: CLIENT, redirect_uris: ['https://client.example/callback'],
    token_endpoint_auth_method: 'private_key_jwt', grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'], scope: 'atproto', dpop_bound_access_tokens: true, jwks: { keys },
  }, CLIENT);
}

describe('confidential OAuth client key binding', () => {
  it('pins the verified key and rejects missing kids and same-kid key replacement', async () => {
    const env = await makeEnv();
    const original = await generateKeyPair('ES256');
    const replacement = await generateKeyPair('ES256');
    const originalJwk = await exportJWK(original.publicKey);
    const replacementJwk = await exportJWK(replacement.publicKey);
    const expected = { method: 'private_key_jwt', keyId: await jwkThumbprint(originalJwk), keyBinding: 'jwk-thumbprint-v1' };

    await expect(verifyClientAuthentication(env, CLIENT, ISSUER,
      metadata([{ ...replacementJwk, kid: 'other' }]), await assertion(replacement.privateKey, 'original'), { deferReplay: true }))
      .rejects.toThrow('invalid client assertion');
    await expect(requireSameClientAuth(env, CLIENT, ISSUER,
      metadata([{ ...replacementJwk, kid: 'original' }]), await assertion(replacement.privateKey, 'original'), expected, { deferReplay: true }))
      .rejects.toThrow('client authentication key changed');
    await expect(requireSameClientAuth(env, CLIENT, ISSUER,
      metadata([{ ...originalJwk, kid: 'shared' }, { ...replacementJwk, kid: 'shared' }]),
      await assertion(replacement.privateKey, 'shared'), expected, { deferReplay: true }))
      .rejects.toThrow('client authentication key changed');
    const now = Math.floor(Date.now() / 1000);
    const malformedKid = await new SignJWT({ iss: CLIENT, sub: CLIENT, aud: ISSUER, iat: now, exp: now + 60, jti: crypto.randomUUID() })
      .setProtectedHeader({ alg: 'ES256', kid: 42 } as never).sign(original.privateKey);
    await expect(verifyClientAuthentication(env, CLIENT, ISSUER, metadata([{ ...originalJwk, kid: 'original' }]),
      new URLSearchParams({ client_assertion_type: TYPE, client_assertion: malformedKid }), { deferReplay: true }))
      .rejects.toThrow('invalid client assertion');
    const rotatedKid = await requireSameClientAuth(env, CLIENT, ISSUER,
      metadata([{ ...originalJwk, kid: 'new-kid' }]), await assertion(original.privateKey, 'new-kid'), expected, { deferReplay: true });
    expect(rotatedKid.keyId).toBe(expected.keyId);
    const noKid = await requireSameClientAuth(env, CLIENT, ISSUER,
      metadata([{ ...originalJwk, kid: 'new-kid' }]), await assertion(original.privateKey), expected, { deferReplay: true });
    expect(noKid.keyId).toBe(expected.keyId);
  });

  it('requires an explicit version even when a legacy key ID happens to equal a thumbprint', async () => {
    const env = await makeEnv();
    for (const keyId of [null, 'legacy-kid', 'any-thumbprint']) {
      await expect(requireStoredClientAuthentication(env, CLIENT, ISSUER, new URLSearchParams(),
        { method: 'private_key_jwt', keyId })).rejects.toThrow('renewed authorization');
    }
  });
});
