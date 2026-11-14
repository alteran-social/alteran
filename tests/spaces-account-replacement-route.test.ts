import { expect } from '@std/expect';
import { authorizedReadFixture, interceptRead, COLLECTION, DID, SPACE } from './helpers/spaces-authorized-read';
import { createAccount } from '../src/db/account';
import { setAccountState } from '../src/db/dal';
import { createExplicitSpaceConsent } from '../src/lib/spaces/explicit-read-consent';
import { issueSessionTokens } from '../src/lib/session-tokens';
import { createOAuthSession } from './helpers/oauth-store';
import { makeDpopKey, signResourceDpop } from './helpers/oauth';
import { verifyResourceRequest } from '../src/lib/oauth/resource';
import { readAuthorizedSpaceRecord } from '../src/db/space-authorized-record';
import { GET } from '../src/pages/xrpc/com.atproto.space.getRecord';

Deno.test({ name: 'a newly authorized account cannot read the prior incarnation private record',
  sanitizeOps: false, sanitizeResources: false, async fn() {
    const { env } = await authorizedReadFixture();
    await env.ALTERAN_DB.prepare('DELETE FROM account WHERE did = ?').bind(DID).run();
    await env.ALTERAN_DB.prepare('DELETE FROM account_state WHERE did = ?').bind(DID).run();
    expect(await createAccount(env, { did: DID, handle: 'test.example', passwordScrypt: null })).toBe(true);
    await setAccountState(env, DID, { tag: 'active' });
    const account = await env.ALTERAN_DB.prepare('SELECT space_incarnation FROM account WHERE did = ?').bind(DID).first();
    const key = await makeDpopKey(), clientId = 'https://client.example/metadata';
    const consent = await createExplicitSpaceConsent({
      subject: DID, accountIncarnation: account!.space_incarnation as string, clientId, dpopJkt: key.jkt,
      clientAuthMethod: 'none', clientAuthKeyId: null, clientAuthKeyBinding: null,
    }, 'atproto space:com.example.notes?skey=read-record&collection=com.example.note&action=read_self');
    if (!consent) throw new Error('Missing consent');
    const sessionId = crypto.randomUUID().replaceAll('-', ''), accessJti = crypto.randomUUID().replaceAll('-', '');
    const token = await issueSessionTokens(env, DID, { accessScope: consent.tokenScope, clientId, dpopJkt: key.jkt,
      oauthSessionId: sessionId, accessJti, spaceGrantDigest: consent.digest });
    await createOAuthSession(env, { id: sessionId, did: DID, clientId, clientAuthMethod: 'none', dpopJkt: key.jkt,
      scope: consent.tokenScope, currentRefreshTokenId: token.refreshPayload.jti, accessJti, expiresAt: token.refreshExpiry });
    await env.ALTERAN_DB.prepare('INSERT INTO oauth_space_grant (session_id, snapshot, digest, created_at) VALUES (?, ?, ?, unixepoch())')
      .bind(sessionId, consent.serialized, consent.digest).run();

    const path = 'https://pds.example/xrpc/com.atproto.space.getRecord';
    const url = `${path}?${new URLSearchParams({ space: SPACE, repo: DID, collection: COLLECTION, rkey: 'one' })}`;
    async function request() {
      return new Request(url, { headers: { authorization: `DPoP ${token.accessJwt}`,
        dpop: await signResourceDpop(env, key, 'GET', path, token.accessJwt) } });
    }
    const watched = interceptRead(env);
    const first = await request();
    const auth = await verifyResourceRequest(watched.env, first);
    if (!auth?.spacePrincipal) throw new Error('Missing signed Space principal');
    watched.arm();
    const result = await readAuthorizedSpaceRecord(watched.env, auth.spacePrincipal, first, SPACE, DID, COLLECTION, 'one');
    if (result.tag === 'found') throw new Error('Transferred a prior-incarnation record');
    if (result.tag === 'notFound') expect(await result.complete(first, watched.env.ALTERAN_DB)).toBe(false);
    const rows = watched.returned() as { sentinel: number; value_cbor: unknown }[];
    expect(rows.filter((row) => row.sentinel === 0)).toEqual([]);
    expect(rows.every((row) => row.value_cbor === null)).toBe(true);
    const second = await request();
    const response = await GET({ locals: { env }, request: second, url: new URL(second.url) } as never);
    expect(response.status).toBe(401);
    expect(response.headers.get('cache-control')).toBe('private, no-store');
  },
});
