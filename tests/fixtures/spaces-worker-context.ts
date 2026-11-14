import { exportJWK, generateKeyPair } from 'jose';
import type { Env } from '../../src/env';
import { createAccount } from '../../src/db/account';
import { setAccountState } from '../../src/db/dal';
import { createPersonalSpace } from '../../src/db/space-lifecycle-create';
import { applySpaceWrites } from '../../src/db/space-store';
import { readAuthorizedSpaceRecord } from '../../src/db/space-authorized-record';
import { jwkThumbprint } from '../../src/lib/oauth/dpop';
import { dpopResourceUnauthorized, verifyResourceRequest } from '../../src/lib/oauth/resource';
import { issueSessionTokens } from '../../src/lib/session-tokens';
import { createExplicitSpaceConsent } from '../../src/lib/spaces/explicit-read-consent';

const DID = 'did:example:test';
const SPACE = `at://${DID}/space/com.example.notes/worker-context`;
const COLLECTION = 'com.example.note';
const CLIENT = 'https://client.example/metadata';

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === '/setup') return setup(env, url.searchParams.has('collection-free'));
    try {
      const auth = await verifyResourceRequest(env, request);
      if (!auth?.spacePrincipal) return new Response(null, { status: 401 });
      const forwarded = url.searchParams.has('clone') ? request.clone() as unknown as Request : request;
      const result = await readAuthorizedSpaceRecord(env, auth.spacePrincipal, forwarded, SPACE, DID, COLLECTION, 'one');
      return Response.json({ tag: result.tag });
    } catch {
      return new Response(null, { status: 401 });
    }
  },
};

async function setup(env: Env, collectionFree: boolean): Promise<Response> {
  await createAccount(env, { did: DID, handle: 'test.example', passwordScrypt: null });
  await setAccountState(env, DID, { tag: 'active' });
  const account = await env.ALTERAN_DB.prepare('SELECT space_incarnation FROM account WHERE did = ?')
    .bind(DID).first<{ space_incarnation: string }>();
  if (!account) throw new Error('Missing test account');
  await createPersonalSpace(env, SPACE, { $type: 'com.atproto.personalspace.policy' }, crypto.randomUUID(), account.space_incarnation);
  await applySpaceWrites(env, SPACE, DID, [{
    action: 'create', collection: COLLECTION, rkey: 'one', record: { $type: COLLECTION, text: 'worker context' },
  }], account.space_incarnation);
  const pair = await generateKeyPair('ES256', { extractable: true });
  const publicJwk = await exportJWK(pair.publicKey);
  const privateJwk = await exportJWK(pair.privateKey);
  const jkt = await jwkThumbprint(publicJwk as JsonWebKey);
  const consent = await createExplicitSpaceConsent({ subject: DID, accountIncarnation: account.space_incarnation,
    clientId: CLIENT, dpopJkt: jkt, clientAuthMethod: 'none', clientAuthKeyId: null, clientAuthKeyBinding: null },
    `atproto space:com.example.notes?skey=worker-context&${collectionFree ? '' : `collection=${COLLECTION}&`}action=read_self`);
  if (!consent) throw new Error('Invalid test consent');
  const session = crypto.randomUUID().replaceAll('-', ''), accessJti = crypto.randomUUID().replaceAll('-', '');
  const tokens = await issueSessionTokens(env, DID, { clientId: CLIENT, dpopJkt: jkt, oauthSessionId: session,
    accessJti, accessScope: consent.tokenScope, spaceGrantDigest: consent.digest });
  const now = Math.floor(Date.now() / 1000);
  await env.ALTERAN_DB.prepare(`INSERT INTO oauth_session
    (id, did, client_id, client_auth_method, client_auth_key_id, client_auth_key_binding, dpop_jkt, scope,
     current_refresh_token_id, access_jti, created_at, updated_at, expires_at, revoked_at)
    VALUES (?, ?, ?, 'none', NULL, NULL, ?, ?, ?, ?, ?, ?, ?, NULL)`)
    .bind(session, DID, CLIENT, jkt, consent.tokenScope, tokens.refreshPayload.jti, accessJti,
      now, now, tokens.refreshExpiry).run();
  await env.ALTERAN_DB.prepare('INSERT INTO oauth_space_grant (session_id, snapshot, digest, created_at) VALUES (?, ?, ?, ?)')
    .bind(session, consent.serialized, consent.digest, now).run();
  const nonce = (await dpopResourceUnauthorized(env)).headers.get('DPoP-Nonce');
  if (!nonce) throw new Error('Missing test nonce');
  return Response.json({ access: tokens.accessJwt, publicJwk, privateJwk, nonce, space: SPACE, repo: DID, collection: COLLECTION });
}
