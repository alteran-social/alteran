import { makeEnv } from './env';
import { makeDpopKey, signResourceDpop } from './oauth';
import { createOAuthSession } from './oauth-store';
import { createAccount, getSecret } from '../../src/db/account';
import { SignJWT } from 'jose';
import { setAccountState } from '../../src/db/dal';
import { createPersonalSpace } from '../../src/db/space-lifecycle-create';
import { applySpaceWrites } from '../../src/db/space-store';
import { createExplicitSpaceConsent } from '../../src/lib/spaces/explicit-read-consent';
import { issueSessionTokens } from '../../src/lib/session-tokens';
import { verifyResourceRequest } from '../../src/lib/oauth/resource';

export const DID = 'did:example:test';
export const SPACE = `at://${DID}/space/com.example.notes/read-record`;
export const COLLECTION = 'com.example.note';
export const OTHER_COLLECTION = 'com.example.other';
const CLIENT = 'https://client.example/metadata';
const REQUEST_SCOPE = 'atproto space:com.example.notes?skey=read-record&collection=com.example.note&action=read_self';
const RESOURCE = 'https://pds.example/xrpc/com.atproto.space.getRecord';

/** Issue a real signed token and proof against a stored consent snapshot. */
export async function authorizedReadFixture(accessLifetime?: number) {
  const env = await makeEnv();
  await createAccount(env, { did: DID, handle: 'test.example', passwordScrypt: null });
  await setAccountState(env, DID, { tag: 'active' });
  const account = await env.ALTERAN_DB.prepare('SELECT space_incarnation FROM account WHERE did = ?')
    .bind(DID).first<{ space_incarnation: string }>();
  if (!account) throw new Error('Missing test account');
  await createPersonalSpace(env, SPACE, { $type: 'com.atproto.personalspace.policy' }, crypto.randomUUID());
  await applySpaceWrites(env, SPACE, DID, [
    { action: 'create', collection: COLLECTION, rkey: 'one', record: { $type: COLLECTION, text: 'private' } },
    { action: 'create', collection: OTHER_COLLECTION, rkey: 'two', record: { $type: OTHER_COLLECTION, text: 'also private' } },
  ]);
  const key = await makeDpopKey();
  const consent = await createExplicitSpaceConsent({
    subject: DID, accountIncarnation: account.space_incarnation, clientId: CLIENT, dpopJkt: key.jkt, clientAuthMethod: 'none',
    clientAuthKeyId: null, clientAuthKeyBinding: null,
  }, REQUEST_SCOPE);
  if (!consent) throw new Error('Invalid test consent');
  const sessionId = crypto.randomUUID().replaceAll('-', '');
  const accessJti = crypto.randomUUID().replaceAll('-', '');
  const tokens = await issueSessionTokens(env, DID, {
    accessScope: consent.tokenScope, clientId: CLIENT, dpopJkt: key.jkt,
    oauthSessionId: sessionId, accessJti, spaceGrantDigest: consent.digest,
  });
  let accessToken = tokens.accessJwt;
  if (accessLifetime !== undefined) {
    const signingSecret = await getSecret(env, 'session_jwt_secret');
    if (!signingSecret) throw new Error('Missing test signing secret');
    accessToken = await new SignJWT({ ...tokens.accessPayload, exp: tokens.accessPayload.iat + accessLifetime })
      .setProtectedHeader({ alg: 'HS256', typ: 'at+jwt' }).sign(new TextEncoder().encode(signingSecret));
  }
  await createOAuthSession(env, {
    id: sessionId, did: DID, clientId: CLIENT, clientAuthMethod: 'none', dpopJkt: key.jkt,
    scope: consent.tokenScope, currentRefreshTokenId: tokens.refreshPayload.jti,
    accessJti, expiresAt: tokens.refreshExpiry,
  });
  await env.ALTERAN_DB.prepare('INSERT INTO oauth_space_grant (session_id, snapshot, digest, created_at) VALUES (?, ?, ?, unixepoch())')
    .bind(sessionId, consent.serialized, consent.digest).run();
  async function principal(
    target = { space: SPACE, repo: DID, collection: COLLECTION, rkey: 'one' },
    requestEnv = env,
    controller?: AbortController,
    querySuffix = '',
  ) {
    const proof = await signResourceDpop(requestEnv, key, 'GET', RESOURCE, accessToken);
    const request = new Request(`${RESOURCE}?${new URLSearchParams(target)}${querySuffix}`, {
      headers: { authorization: `DPoP ${accessToken}`, dpop: proof },
      signal: controller?.signal,
    });
    const context = await verifyResourceRequest(requestEnv, request);
    if (!context?.spacePrincipal) throw new Error('No verified Space principal');
    return { principal: context.spacePrincipal, request };
  }
  return { env, key, sessionId, tokens, principal };
}

type TestEnv = Awaited<ReturnType<typeof makeEnv>>;

/** Observe the authorized SELECT and optionally change state just before or after its transaction. */
export function interceptRead(
  env: TestEnv,
  callbacks: {
    before?: () => Promise<void>;
    after?: (result: unknown[]) => Promise<void> | void;
  } = {},
) {
  const db = env.ALTERAN_DB;
  let returned: unknown;
  let armed = false;
  const wrapped = new Proxy(db, { get(target, key) {
    if (key === 'batch') return async (statements: Parameters<typeof db.batch>[0]) => {
      if (!armed || statements.length !== 6) return db.batch(statements);
      await callbacks.before?.();
      const result = await db.batch(statements);
      returned = result[2]?.results;
      await callbacks.after?.(result);
      return result;
    };
    const value = Reflect.get(target, key, target);
    return typeof value === 'function' ? value.bind(target) : value;
  } });
  return { env: { ...env, ALTERAN_DB: wrapped }, arm: () => { armed = true; }, returned: () => returned };
}
