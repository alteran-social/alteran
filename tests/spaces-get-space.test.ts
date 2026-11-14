import { expect } from '@std/expect';
import { describe, it } from './helpers/bdd';
import { DID, SPACE } from './helpers/spaces-authorized-read';
import { EMPTY, ENDPOINT, MISSING, policyContext, policyFixture, signedPolicyRequest } from './helpers/spaces-policy-read';
import { beginPersonalSpaceDeletion } from '../src/db/space-lifecycle-delete';
import { createOAuthSession } from './helpers/oauth-store';
import { issueSessionTokens } from '../src/lib/session-tokens';
import { AuthScope } from '../src/lib/auth-scope';
import { GET, HEAD, ALL } from '../src/pages/xrpc/com.atproto.space.getSpace';

function assertPrivate(response: Response) {
  expect(response.headers.get('cache-control')).toBe('private, no-store');
  const vary = (response.headers.get('vary') ?? '').toLowerCase();
  for (const value of ['authorization', 'dpop', 'accept-signature']) expect(vary).toContain(value);
}

describe('owner-only Space getSpace route', () => {
  it('returns the same personal policy before and after a repo exists', async () => {
    const f = await policyFixture();
    const row = await f.env.ALTERAN_DB.prepare('SELECT COUNT(*) AS n FROM space_repo WHERE space_ref = ?')
      .bind(EMPTY).first<{ n: number }>();
    expect(row?.n).toBe(0);
    for (const space of [EMPTY, SPACE]) {
      const response = await GET(policyContext(f.env, await signedPolicyRequest(f, space)));
      expect(response.status).toBe(200);
      expect(await response.json()).toEqual({ space, policy: { $type: 'com.atproto.personalspace.policy' } });
      assertPrivate(response);
    }
    const missing = await GET(policyContext(f.env, await signedPolicyRequest(f, MISSING)));
    expect(missing.status).toBe(400);
    expect(await missing.json()).toEqual({ error: 'SpaceNotFound', message: 'Space not found' });
    assertPrivate(missing);
  });

  it('hides deleted and unowned legacy policy rows as absent', async () => {
    const f = await policyFixture();
    const deleted = await beginPersonalSpaceDeletion(f.env, EMPTY, crypto.randomUUID(), f.owner.incarnation);
    expect(deleted.tag).toBe('started');
    const tombstone = await GET(policyContext(f.env, await signedPolicyRequest(f, EMPTY)));
    expect(tombstone.status).toBe(400);
    expect((await tombstone.json() as { error: string }).error).toBe('SpaceNotFound');
    await f.env.ALTERAN_DB.prepare('DROP TRIGGER space_personal_policy_update').run();
    await f.env.ALTERAN_DB.prepare('UPDATE space_personal_policy SET authority_incarnation = NULL WHERE space_ref = ?')
      .bind(SPACE).run();
    const legacy = await GET(policyContext(f.env, await signedPolicyRequest(f, SPACE)));
    expect(legacy.status).toBe(400);
    expect((await legacy.json() as { error: string }).error).toBe('SpaceNotFound');
  });

  it('validates exact parameters, bound headers, target scope and proof replay', async () => {
    const f = await policyFixture();
    const first = await signedPolicyRequest(f);
    const proof = first.headers.get('dpop') ?? '';
    for (const query of ['', 'space=invalid', `${new URLSearchParams({ space: EMPTY })}&space=${encodeURIComponent(EMPTY)}`,
      `${new URLSearchParams({ space: EMPTY })}&repo=${encodeURIComponent(DID)}`, `space=${'x'.repeat(17_000)}`]) {
      const response = await GET(policyContext(f.env, await signedPolicyRequest(f, EMPTY, { query, proof })));
      expect(response.status).toBe(400);
      assertPrivate(response);
    }
    const mac = await GET(policyContext(f.env, await signedPolicyRequest(f, EMPTY, {
      proof, headers: { 'accept-signature': 'sig1' },
    })));
    expect(mac.status).toBe(400);
    expect((await mac.json() as { error: string }).error).toBe('InvalidRequest');
    expect((await GET(policyContext(f.env, first))).status).toBe(200);
    const replay = await GET(policyContext(f.env, await signedPolicyRequest(f, MISSING, { proof })));
    expect(replay.status).toBe(400);
    for (const space of [`at://did:example:other/space/com.example.notes/empty-policy`,
      `at://${DID}/space/com.example.other/empty-policy`]) {
      const denied = await GET(policyContext(f.env, await signedPolicyRequest(f, space)));
      expect(denied.status).toBe(401);
      assertPrivate(denied);
    }
    const noAuth = await GET(policyContext(f.env, new Request(`${ENDPOINT}?${new URLSearchParams({ space: EMPTY })}`)));
    expect(noAuth.status).toBe(401);
    expect(noAuth.headers.get('www-authenticate')).toBe('DPoP');
    expect(HEAD().status).toBe(405);
    expect(ALL().status).toBe(405);
    assertPrivate(HEAD());
  });

  it('requires an explicit Space grant and rejects bearer or malformed proofs', async () => {
    const f = await policyFixture();
    const sessionId = crypto.randomUUID(), accessJti = crypto.randomUUID(), clientId = 'https://client.example/metadata';
    const tokens = await issueSessionTokens(f.env, DID, {
      accessScope: 'atproto transition:generic', clientId, dpopJkt: f.key.jkt, oauthSessionId: sessionId, accessJti,
    });
    await createOAuthSession(f.env, {
      id: sessionId, did: DID, clientId, clientAuthMethod: 'none', dpopJkt: f.key.jkt,
      scope: 'atproto transition:generic', currentRefreshTokenId: tokens.refreshPayload.jti, accessJti, expiresAt: tokens.refreshExpiry,
    });
    const ordinary = { ...f, tokens, sessionId };
    const insufficient = await GET(policyContext(f.env, await signedPolicyRequest(ordinary)));
    expect(insufficient.status).toBe(403);
    expect((await insufficient.json() as { error: string }).error).toBe('ScopeMissingError');
    const legacy = await issueSessionTokens(f.env, DID, { accessScope: AuthScope.AppPass });
    const query = new URLSearchParams({ space: EMPTY });
    const bearer = await GET(policyContext(f.env, new Request(`${ENDPOINT}?${query}`, {
      headers: { authorization: `Bearer ${legacy.accessJwt}` },
    })));
    expect(bearer.status).toBe(401);
    const malformed = await GET(policyContext(f.env, await signedPolicyRequest(f, EMPTY, { proof: 'bad.proof.value' })));
    expect(malformed.status).toBe(401);
    expect(malformed.headers.get('dpop-nonce')).toBeTruthy();
    expect(malformed.headers.get('access-control-expose-headers')?.toLowerCase()).toContain('dpop-nonce');
    const oversized = new Request(`${ENDPOINT}?${query}`, { headers: { authorization: 'DPoP token', dpop: 'x'.repeat(16_385) } });
    expect((await GET(policyContext(f.env, oversized))).status).toBe(400);
    assertPrivate(malformed);
  });
});
