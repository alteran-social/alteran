import { expect } from '@std/expect';
import { describe, it } from './helpers/bdd';
import { DID, interceptRead } from './helpers/spaces-authorized-read';
import { EMPTY, MISSING, policyContext, policyFixture, policyPrincipal, policySession, signedPolicyRequest } from './helpers/spaces-policy-read';
import { createAccount } from '../src/db/account';
import { setAccountState } from '../src/db/dal';
import { createPersonalSpace } from '../src/db/space-lifecycle-create';
import { beginPersonalSpaceDeletion } from '../src/db/space-lifecycle-delete';
import { readAuthorizedSpacePolicy } from '../src/db/space-authorized-policy';
import type { VerifiedSpacePrincipal } from '../src/lib/oauth/space-principal';
import { GET } from '../src/pages/xrpc/com.atproto.space.getSpace';

describe('Space policy authorization races', () => {
  it('projects no policy identity if revocation precedes the D1 selection', async () => {
    const f = await policyFixture();
    const watched = interceptRead(f.env, { before: async () => {
      await f.env.ALTERAN_DB.prepare('UPDATE oauth_session SET revoked_at = unixepoch() WHERE id = ?').bind(f.sessionId).run();
    } });
    const request = await signedPolicyRequest(f, EMPTY, { env: watched.env });
    watched.arm();
    const response = await GET(policyContext(watched.env, request));
    expect(response.status).toBe(401);
    expect(watched.returned()).toEqual([]);
  });

  it('denies found and absent results when state changes after selection', async () => {
    for (const mode of ['revoked', 'rotated', 'deleted', 'created', 'expired', 'cancelled', 'account', 'database'] as const) {
      const f = await policyFixture();
      const controller = new AbortController();
      const target = mode === 'created' ? MISSING : EMPTY;
      const watched = interceptRead(f.env, { after: async () => {
        if (mode === 'revoked') await f.env.ALTERAN_DB.prepare('UPDATE oauth_session SET revoked_at = unixepoch() WHERE id = ?')
          .bind(f.sessionId).run();
        if (mode === 'rotated') await f.env.ALTERAN_DB.prepare('UPDATE oauth_session SET access_jti = ? WHERE id = ?')
          .bind('new-access-jti', f.sessionId).run();
        if (mode === 'deleted') {
          expect((await beginPersonalSpaceDeletion(f.env, EMPTY, crypto.randomUUID(), f.owner.incarnation)).tag).toBe('started');
        }
        if (mode === 'created') {
          await createPersonalSpace(f.env, MISSING, { $type: 'com.atproto.personalspace.policy' }, crypto.randomUUID(), f.owner.incarnation);
        }
        if (mode === 'expired') await f.env.ALTERAN_DB.prepare('UPDATE oauth_replay_clock SET seconds = ? WHERE id = 1')
          .bind(f.tokens.accessPayload.exp).run();
        if (mode === 'cancelled') controller.abort();
        if (mode === 'account') {
          await f.env.ALTERAN_DB.prepare('DELETE FROM account WHERE did = ?').bind(DID).run();
          await f.env.ALTERAN_DB.prepare('DELETE FROM account_state WHERE did = ?').bind(DID).run();
          await createAccount(f.env, { did: DID, handle: 'test.example', passwordScrypt: null });
          await setAccountState(f.env, DID, { tag: 'active' });
        }
        if (mode === 'database') watched.env.ALTERAN_DB = new Proxy(f.env.ALTERAN_DB, {});
      } });
      const request = await signedPolicyRequest(f, target, { env: watched.env, signal: controller.signal });
      watched.arm();
      const response = await GET(policyContext(watched.env, request));
      expect(response.status).toBe(401);
      const body = await response.text();
      expect(body).not.toContain('personalspace');
      expect(body).not.toContain('SpaceNotFound');
    }
  });

  it('does not expose an old policy to a recreated account', async () => {
    const f = await policyFixture();
    await f.env.ALTERAN_DB.prepare('DELETE FROM account WHERE did = ?').bind(DID).run();
    await f.env.ALTERAN_DB.prepare('DELETE FROM account_state WHERE did = ?').bind(DID).run();
    await createAccount(f.env, { did: DID, handle: 'test.example', passwordScrypt: null });
    await setAccountState(f.env, DID, { tag: 'active' });
    const replacement = await policySession(f.env, f.key);
    expect(replacement.owner.incarnation).not.toBe(f.owner.incarnation);
    const response = await GET(policyContext(replacement.env, await signedPolicyRequest(replacement)));
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: 'SpaceNotFound', message: 'Space not found' });
  });

  it('does not complete if the selected policy identity changes', async () => {
    const f = await policyFixture();
    await f.env.ALTERAN_DB.prepare('DROP TRIGGER space_personal_policy_update').run();
    const watched = interceptRead(f.env, { after: async () => {
      await f.env.ALTERAN_DB.prepare('UPDATE space_personal_policy SET creation_nonce = ? WHERE space_ref = ?')
        .bind(crypto.randomUUID(), EMPTY).run();
    } });
    const request = await signedPolicyRequest(f, EMPTY, { env: watched.env });
    watched.arm();
    const response = await GET(policyContext(watched.env, request));
    expect(response.status).toBe(401);
    expect(await response.text()).not.toContain('personalspace');
  });

  it('consumes the verified principal and binds completion to the request and D1 once', async () => {
    const f = await policyFixture();
    for (const mode of ['valid', 'request', 'database'] as const) {
      const current = await policyPrincipal(f);
      expect((await readAuthorizedSpacePolicy(f.env, { ...current.principal } as VerifiedSpacePrincipal, current.request)).tag)
        .toBe('unauthorized');
      const result = await readAuthorizedSpacePolicy(f.env, current.principal, current.request);
      expect(result.tag).toBe('found');
      if (result.tag !== 'found') throw new Error('Expected personal policy');
      const request = mode === 'request' ? current.request.clone() : current.request;
      const database = mode === 'database' ? new Proxy(f.env.ALTERAN_DB, {}) : f.env.ALTERAN_DB;
      expect(await result.complete(request, database)).toBe(mode === 'valid');
      expect(await result.complete(current.request, f.env.ALTERAN_DB)).toBe(false);
      expect((await readAuthorizedSpacePolicy(f.env, current.principal, current.request)).tag).toBe('unauthorized');
    }
  });

  it('authorizes a serialization error only if access remains live', async () => {
    for (const revoked of [false, true]) {
      const f = await policyFixture();
      const original = JSON.stringify;
      const watched = interceptRead(f.env, { after: async () => {
        if (revoked) await f.env.ALTERAN_DB.prepare('UPDATE oauth_session SET revoked_at = unixepoch() WHERE id = ?')
          .bind(f.sessionId).run();
        JSON.stringify = ((...args: Parameters<typeof JSON.stringify>) => {
          const value = args[0];
          if (value && typeof value === 'object' && 'policy' in value) throw new Error('private serialization failure');
          return Reflect.apply(original, JSON, args);
        }) as typeof JSON.stringify;
      } });
      const request = await signedPolicyRequest(f, EMPTY, { env: watched.env });
      watched.arm();
      try {
        const response = await GET(policyContext(watched.env, request));
        expect(response.status).toBe(revoked ? 401 : 500);
        expect(await response.text()).not.toContain('private serialization failure');
      } finally {
        JSON.stringify = original;
      }
    }
  });
});
