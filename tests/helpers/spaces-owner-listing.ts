import { makeEnv } from './env';
import { makeDpopKey, signResourceDpop } from './oauth';
import { createOAuthSession } from './oauth-store';
import { createAccount } from '../../src/db/account';
import { setAccountState } from '../../src/db/dal';
import { createPersonalSpace } from '../../src/db/space-lifecycle-create';
import { createExplicitSpaceConsent } from '../../src/lib/spaces/explicit-read-consent';
import { issueSessionTokens } from '../../src/lib/session-tokens';

export const DID = 'did:example:test';
export const TYPE = 'com.example.notes';
const CLIENT = 'https://client.example/metadata';
export const ENDPOINT = 'https://pds.example/xrpc/com.atproto.space.listSpaces';
const POLICY = { $type: 'com.atproto.personalspace.policy' };
export const refForType = (skey: string, spaceType: string) => `at://${DID}/space/${spaceType}/${skey}`;
export const ref = (skey: string) => refForType(skey, TYPE);

export async function fixture(skey = '*', existing?: Awaited<ReturnType<typeof makeEnv>>, spaceType = TYPE) {
  const env = existing ?? await makeEnv();
  await createAccount(env, { did: DID, handle: 'test.example', passwordScrypt: null });
  await setAccountState(env, DID, { tag: 'active' });
  const account = await env.ALTERAN_DB.prepare('SELECT space_incarnation FROM account WHERE did = ?')
    .bind(DID).first<{ space_incarnation: string }>();
  if (!account) throw new Error('Missing test account');
  const key = await makeDpopKey();
  const scope = `atproto space:${spaceType}?skey=${encodeURIComponent(skey)}&action=read_self`;
  const consent = await createExplicitSpaceConsent({ subject: DID, accountIncarnation: account.space_incarnation,
    clientId: CLIENT, dpopJkt: key.jkt, clientAuthMethod: 'none', clientAuthKeyId: null, clientAuthKeyBinding: null }, scope);
  if (!consent) throw new Error('Invalid test consent');
  const sessionId = crypto.randomUUID().replaceAll('-', '');
  const accessJti = crypto.randomUUID().replaceAll('-', '');
  const tokens = await issueSessionTokens(env, DID, { accessScope: consent.tokenScope, clientId: CLIENT, dpopJkt: key.jkt,
    oauthSessionId: sessionId, accessJti, spaceGrantDigest: consent.digest });
  await createOAuthSession(env, { id: sessionId, did: DID, clientId: CLIENT, clientAuthMethod: 'none', dpopJkt: key.jkt,
    scope: consent.tokenScope, currentRefreshTokenId: tokens.refreshPayload.jti, accessJti, expiresAt: tokens.refreshExpiry });
  await env.ALTERAN_DB.prepare('INSERT INTO oauth_space_grant (session_id, snapshot, digest, created_at) VALUES (?, ?, ?, unixepoch())')
    .bind(sessionId, consent.serialized, consent.digest).run();
  async function request(parameters: Record<string, string> = {}) {
    const query = new URLSearchParams({ spaceDid: DID, spaceType, ...parameters });
    return new Request(`${ENDPOINT}?${query}`, { headers: { authorization: `DPoP ${tokens.accessJwt}`,
      dpop: await signResourceDpop(env, key, 'GET', ENDPOINT, tokens.accessJwt) } });
  }
  async function create(skey: string) {
    await createPersonalSpace(env, refForType(skey, spaceType), POLICY, crypto.randomUUID(), account.space_incarnation);
  }
  return { env, account, key, tokens, request, create, sessionId };
}

export function context(env: Awaited<ReturnType<typeof makeEnv>>, request: Request) {
  return { locals: { env }, request, url: new URL(request.url) } as never;
}
