import type { Env } from '../../env';
import { getOrCreateSecret } from '../../db/account';
import { jwkThumbprint } from './dpop';

const AS_SIGNING_KEY = 'oauth:as:signing-key';

export async function getAuthorizationServerPublicJwk(env: Env): Promise<JsonWebKey> {
  const privateJwkJson = await getOrCreateSecret(env, AS_SIGNING_KEY, async () => {
    const keyPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify'],
    );
    const privateJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
    return JSON.stringify(privateJwk);
  });

  const privateJwk = JSON.parse(privateJwkJson) as JsonWebKey;
  const publicJwk: JsonWebKey = {
    kty: privateJwk.kty,
    crv: privateJwk.crv,
    x: privateJwk.x,
    y: privateJwk.y,
    key_ops: ['verify'],
    ext: true,
  };
  const kid = await jwkThumbprint(publicJwk);
  return { ...publicJwk, kid, alg: 'ES256', use: 'sig' } as JsonWebKey;
}
