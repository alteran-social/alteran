import type { APIContext } from 'astro';
import { expect } from '@std/expect';
import { describe, it } from './helpers/bdd';
import { makeEnv } from './helpers/env';
import { makeDpopKey, signDpopProof } from './helpers/oauth';
import { saveCode } from './helpers/oauth-store';
import { getSecret } from '../src/db/account';
import { sha256b64url } from '../src/lib/oauth/dpop';
import { loadCodeSnapshot, parRecordFits } from '../src/lib/oauth/store';
import { POST } from '../src/pages/oauth/token';

const CLIENT = 'https://client.example/metadata';
const URL = 'https://pds.example/oauth/token';
const REDIRECT = 'https://client.example/callback';
const VERIFIER = 'snapshot-boundary-verifier';

function scopeNear(maximum: number): string {
  let scope = 'atproto';
  for (let index = 0; ; index++) {
    const next = ` repo:com.example.collection${index}?action=create`;
    if (scope.length + next.length > maximum) return scope;
    scope += next;
  }
}

describe('OAuth snapshot size compatibility', () => {
  for (const sample of [{ size: 60_000, succeeds: true }, { size: 63_400, succeeds: false }]) {
    it(sample.succeeds ? 'refreshes a near-limit issued grant' : 'rejects an oversized grant before consuming its code or proof', async () => {
      const env = await makeEnv();
      const key = await makeDpopKey();
      const code = crypto.randomUUID();
      const scope = scopeNear(sample.size);
      const did = `did:example:${'x'.repeat(2000)}`;
      const now = Math.floor(Date.now() / 1000);
      const codeChallenge = await sha256b64url(VERIFIER);
      expect(parRecordFits({ client_id: CLIENT, redirect_uri: REDIRECT, code_challenge: codeChallenge,
        code_challenge_method: 'S256', scope, state: '', dpopJkt: key.jkt, clientAuthMethod: 'none',
        createdAt: now, expiresAt: now + 300 })).toBe(true);
      await saveCode(env, code, { code, client_id: CLIENT, redirect_uri: REDIRECT, code_challenge: codeChallenge,
        scope, dpopJkt: key.jkt, clientAuthMethod: 'none', did, createdAt: now, expiresAt: now + 300 });
      const jti = crypto.randomUUID();
      const proof = await signDpopProof({ key, method: 'POST', url: URL, jti });
      const request = new Request(URL, { method: 'POST', headers: { DPoP: proof }, body: new URLSearchParams({
        grant_type: 'authorization_code', code, client_id: CLIENT, redirect_uri: REDIRECT, code_verifier: VERIFIER,
      }) });
      const exchange = await POST({ locals: { env }, request } as unknown as APIContext);
      if (!sample.succeeds) {
        expect(exchange.status).toBe(400);
        expect(await loadCodeSnapshot(env, code)).not.toBeNull();
        expect(await getSecret(env, `oauth:dpop:jti:authz:${jti}`)).toBeNull();
        return;
      }
      expect(exchange.status).toBe(200);
      const token = (await exchange.json() as { refresh_token: string }).refresh_token;
      const nextProof = await signDpopProof({ key, method: 'POST', url: URL });
      const refresh = new Request(URL, { method: 'POST', headers: { DPoP: nextProof }, body: new URLSearchParams({
        grant_type: 'refresh_token', refresh_token: token, client_id: CLIENT,
      }) });
      expect((await POST({ locals: { env }, request: refresh } as unknown as APIContext)).status).toBe(200);
    });
  }
});
