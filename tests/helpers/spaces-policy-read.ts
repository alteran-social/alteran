import { authorizedReadFixture, DID } from './spaces-authorized-read';
import { signResourceDpop } from './oauth';
import { createOAuthSession } from './oauth-store';
import { loadActiveSpaceOwner } from '../../src/db/space-owner';
import { createPersonalSpace } from '../../src/db/space-lifecycle-create';
import { createExplicitSpaceConsent } from '../../src/lib/spaces/explicit-read-consent';
import { issueSessionTokens } from '../../src/lib/session-tokens';
import { verifyResourceRequest } from '../../src/lib/oauth/resource';

export const ENDPOINT = 'https://pds.example/xrpc/com.atproto.space.getSpace';
export const EMPTY = `at://${DID}/space/com.example.notes/empty-policy`;
export const MISSING = `at://${DID}/space/com.example.notes/missing-policy`;
type BaseFixture = Awaited<ReturnType<typeof authorizedReadFixture>>;

/** Keep one Space with records and one newly created Space with no repo epoch. */
export async function policyFixture() {
  const fixture = await authorizedReadFixture();
  const owner = await loadActiveSpaceOwner(fixture.env, DID);
  if (!owner) throw new Error('Missing policy owner');
  await createPersonalSpace(fixture.env, EMPTY, { $type: 'com.atproto.personalspace.policy' }, crypto.randomUUID(), owner.incarnation);
  return await policySession(fixture.env, fixture.key);
}

export async function policySession(env: BaseFixture['env'], key: BaseFixture['key']) {
  const owner = await loadActiveSpaceOwner(env, DID);
  if (!owner) throw new Error('Missing policy owner');
  const clientId = 'https://client.example/metadata';
  const consent = await createExplicitSpaceConsent({
    subject: DID, accountIncarnation: owner.incarnation, clientId, dpopJkt: key.jkt,
    clientAuthMethod: 'none', clientAuthKeyId: null, clientAuthKeyBinding: null,
  }, 'atproto space:com.example.notes?action=read_self');
  if (!consent) throw new Error('Missing policy consent');
  const sessionId = crypto.randomUUID().replaceAll('-', ''), accessJti = crypto.randomUUID().replaceAll('-', '');
  const tokens = await issueSessionTokens(env, DID, {
    accessScope: consent.tokenScope, clientId, dpopJkt: key.jkt,
    oauthSessionId: sessionId, accessJti, spaceGrantDigest: consent.digest,
  });
  await createOAuthSession(env, {
    id: sessionId, did: DID, clientId, clientAuthMethod: 'none', dpopJkt: key.jkt,
    scope: consent.tokenScope, currentRefreshTokenId: tokens.refreshPayload.jti, accessJti, expiresAt: tokens.refreshExpiry,
  });
  await env.ALTERAN_DB.prepare('INSERT INTO oauth_space_grant (session_id, snapshot, digest, created_at) VALUES (?, ?, ?, unixepoch())')
    .bind(sessionId, consent.serialized, consent.digest).run();
  return { env, key, owner, tokens, sessionId };
}

type Fixture = Awaited<ReturnType<typeof policyFixture>>;
type Environment = Fixture['env'];

export async function signedPolicyRequest(f: Fixture, space = EMPTY, options: {
  env?: Environment; signal?: AbortSignal; proof?: string; query?: string; headers?: HeadersInit;
} = {}) {
  const env = options.env ?? f.env;
  const dpop = options.proof ?? await signResourceDpop(env, f.key, 'GET', ENDPOINT, f.tokens.accessJwt);
  const headers = new Headers(options.headers);
  headers.set('authorization', `DPoP ${f.tokens.accessJwt}`);
  headers.set('dpop', dpop);
  return new Request(`${ENDPOINT}?${options.query ?? new URLSearchParams({ space })}`, { headers, signal: options.signal });
}

export async function policyPrincipal(f: Fixture, space = EMPTY, env: Environment = f.env, signal?: AbortSignal) {
  const request = await signedPolicyRequest(f, space, { env, signal });
  const context = await verifyResourceRequest(env, request);
  if (!context?.spacePrincipal) throw new Error('Missing verified policy principal');
  return { principal: context.spacePrincipal, request };
}

export function policyContext(env: Environment, request: Request) {
  return { locals: { env }, request, url: new URL(request.url) } as never;
}
