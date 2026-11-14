import { expect } from '@std/expect';
import { describe, it } from './helpers/bdd';
import { DID, SPACE } from './helpers/spaces-authorized-read';
import { EMPTY, MISSING, policyFixture } from './helpers/spaces-policy-read';
import { createOAuthSession } from './helpers/oauth-store';
import { genesisPrincipal, listContext, signedGenesisRequest } from './helpers/spaces-list-genesis';
import { applySpaceWrites } from '../src/db/space-store';
import { createExplicitSpaceConsent } from '../src/lib/spaces/explicit-read-consent';
import { captureRecordIdentity } from '../src/lib/spaces/record-response-input';
import { issueSessionTokens } from '../src/lib/session-tokens';
import { listAuthorizedSpaceRecords } from '../src/db/space-authorized-list';
import { GET } from '../src/pages/xrpc/com.atproto.space.listRecords';

describe('fresh personal Space list', () => {
  it('returns empty pages for value and metadata requests with filters and cursors', async () => {
    const f = await policyFixture();
    const cursor = captureRecordIdentity({ space: EMPTY, repo: DID, collection: 'com.example.note', rkey: 'one' }).uri;
    for (const query of [{}, { excludeValues: 'true' }, { excludeValues: 'false', limit: '1' },
      { collection: 'com.example.note', cursor, limit: '50' }]) {
      const request = await signedGenesisRequest(f, { query });
      const response = await GET(listContext(f.env, request));
      expect(response.status).toBe(200);
      expect(await response.json()).toEqual({ records: [] });
      expect(response.headers.get('cache-control')).toBe('private, no-store');
    }
  });

  it('does not equate missing or foreign-authority Space state with genesis', async () => {
    const f = await policyFixture();
    for (const space of [MISSING, `at://did:example:other/space/com.example.notes/empty-policy`]) {
      const request = await signedGenesisRequest(f, { space });
      expect((await GET(listContext(f.env, request))).status).toBe(401);
    }
    const active = await signedGenesisRequest(f, { space: SPACE });
    const response = await GET(listContext(f.env, active));
    expect(response.status).toBe(200);
    expect((await response.json() as { records: unknown[] }).records.length).toBeGreaterThan(0);
  });

  it('binds the empty result to the exact request and database once', async () => {
    const f = await policyFixture();
    for (const mode of ['valid', 'request', 'database'] as const) {
      const current = await genesisPrincipal(f);
      const result = await listAuthorizedSpaceRecords(f.env, current.principal, current.request);
      expect(result.tag).toBe('found');
      if (result.tag !== 'found') throw new Error('Expected empty list');
      expect(result.records).toEqual([]);
      const request = mode === 'request' ? current.request.clone() : current.request;
      const database = mode === 'database' ? new Proxy(f.env.ALTERAN_DB, {}) : f.env.ALTERAN_DB;
      expect(await result.complete(request, database)).toBe(mode === 'valid');
      expect(await result.complete(current.request, f.env.ALTERAN_DB)).toBe(false);
      expect((await listAuthorizedSpaceRecords(f.env, current.principal, current.request)).tag).toBe('unauthorized');
    }
  });

  it('keeps explicitly granted own-repo reads in another authority Space', async () => {
    const f = await policyFixture();
    const foreign = 'at://did:example:remote/space/com.example.notes/foreign';
    await applySpaceWrites(f.env, foreign, DID, [{ action: 'create', collection: 'com.example.note', rkey: 'one',
      record: { $type: 'com.example.note', text: 'remote-authority' } }], f.owner.incarnation);
    const clientId = 'https://client.example/metadata';
    const consent = await createExplicitSpaceConsent({ subject: DID, accountIncarnation: f.owner.incarnation,
      clientId, dpopJkt: f.key.jkt, clientAuthMethod: 'none', clientAuthKeyId: null, clientAuthKeyBinding: null,
    }, 'atproto space:com.example.notes?authority=*&action=read_self');
    if (!consent) throw new Error('Missing foreign-authority consent');
    const sessionId = crypto.randomUUID().replaceAll('-', ''), accessJti = crypto.randomUUID().replaceAll('-', '');
    const tokens = await issueSessionTokens(f.env, DID, { accessScope: consent.tokenScope, clientId, dpopJkt: f.key.jkt,
      oauthSessionId: sessionId, accessJti, spaceGrantDigest: consent.digest });
    await createOAuthSession(f.env, { id: sessionId, did: DID, clientId, clientAuthMethod: 'none', dpopJkt: f.key.jkt,
      scope: consent.tokenScope, currentRefreshTokenId: tokens.refreshPayload.jti, accessJti, expiresAt: tokens.refreshExpiry });
    await f.env.ALTERAN_DB.prepare('INSERT INTO oauth_space_grant (session_id, snapshot, digest, created_at) VALUES (?, ?, ?, unixepoch())')
      .bind(sessionId, consent.serialized, consent.digest).run();
    const request = await signedGenesisRequest({ ...f, tokens, sessionId }, { space: foreign });
    const response = await GET(listContext(f.env, request));
    expect(response.status).toBe(200);
    expect((await response.json() as { records: unknown[] }).records).toHaveLength(1);
  });
});
