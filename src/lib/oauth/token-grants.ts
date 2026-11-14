import type { Env } from '../../env';
import type { OAuthSessionRow, RefreshTokenRow } from '../../db/account';
import { commitOAuthCodeExchange, commitOAuthRefreshReplay, commitOAuthRefreshRotation, ensureWorkerWindow, OAuthWorkerExpiry, type OAuthIssuedRows } from '../../db/oauth-exchange';
import { loadOAuthRefreshSnapshot, oauthRefreshSnapshotFits, refreshSnapshotValues, sessionSnapshotValues } from '../../db/oauth-exchange-read';
import { validResourceBinding } from '../../db/oauth-replay';
import { prepareReplayTransaction, replayProofBlocked, replayProofExpired, type ReplayTransaction } from '../../db/oauth-replay-transaction';
import { issueSessionTokens, verifyRefreshToken } from '../session-tokens';
import { requireStoredClientAuthentication } from './clients';
import { DpopNonceError } from './dpop-errors';
import { getAuthzNonce, sha256b64url, type DpopVerification } from './dpop';
import { oauthSessionExpiresAt } from './session-lifetime';
import { loadCodeSnapshot } from './store';
import { codeSpaceGrant, sessionSpaceGrant } from './space-grants';
import { loadActiveSpaceIncarnation, type OAuthSpaceGrant } from '../../db/oauth-space-grant';

type GrantContext = { readonly env: Env; readonly form: URLSearchParams; readonly proof: DpopVerification; readonly issuer: string };
export type OAuthGrantResult =
  | { readonly tag: 'ok'; readonly body: Record<string, unknown>; readonly nonce: string }
  | { readonly tag: 'error'; readonly stage: 'auth_code' | 'refresh_token' | 'client_auth'; readonly code: string; readonly description: string };
type RefreshState = { readonly tag: 'current' } | { readonly tag: 'used' } | { readonly tag: 'invalid' };

function invalid(stage: 'auth_code' | 'refresh_token' | 'client_auth', code: string, description: string): OAuthGrantResult {
  return { tag: 'error', stage, code, description };
}

type Issued = { readonly rows: OAuthIssuedRows; readonly accessJwt: string; readonly refreshJwt: string };

async function issueRows(
  env: Env,
  identity: { did: string; clientId: string; method: string; keyId: string | null; keyBinding: string | null; jkt: string; scope: string; spaceGrant?: OAuthSpaceGrant },
  previous?: OAuthSessionRow,
): Promise<Issued> {
  const now = Math.floor(Date.now() / 1000);
  const sessionId = previous?.id ?? crypto.randomUUID().replace(/-/g, '');
  const accessJti = crypto.randomUUID().replace(/-/g, '');
  const tokens = await issueSessionTokens(env, identity.did, {
    accessScope: identity.scope, clientId: identity.clientId, dpopJkt: identity.jkt, oauthSessionId: sessionId, accessJti,
    ...(identity.spaceGrant && { spaceGrantDigest: identity.spaceGrant.digest }),
  });
  const expiresAt = oauthSessionExpiresAt(identity.method, tokens.refreshExpiry, previous
    ? { tag: 'refreshed', currentExpiresAt: previous.expiresAt }
    : { tag: 'created', now });
  const session: OAuthSessionRow = {
    id: sessionId, did: identity.did, clientId: identity.clientId, clientAuthMethod: identity.method,
    clientAuthKeyId: identity.keyId, clientAuthKeyBinding: identity.keyBinding, dpopJkt: identity.jkt,
    scope: identity.scope, currentRefreshTokenId: tokens.refreshPayload.jti, accessJti,
    createdAt: previous?.createdAt ?? now, updatedAt: now, expiresAt, revokedAt: null,
  };
  const refresh: RefreshTokenRow = {
    id: tokens.refreshPayload.jti, did: identity.did, expiresAt, appPasswordName: null, nextId: null,
    tokenKind: 'oauth', oauthSessionId: sessionId, clientId: identity.clientId,
    clientAuthMethod: identity.method, clientAuthKeyId: identity.keyId, dpopJkt: identity.jkt,
    oauthScope: identity.scope, accessJti, revokedAt: null,
  };
  if (!oauthRefreshSnapshotFits(refresh, session) || !validResourceBinding({
    sessionId, accessJti, did: identity.did, clientId: identity.clientId, jkt: identity.jkt,
    scope: identity.scope, expiresAt: tokens.accessPayload.exp,
    ...(identity.spaceGrant && { spaceGrant: identity.spaceGrant }),
  })) throw new Error('OAuth grant exceeds storage limits');
  return { rows: { session, refresh, accessExpiresAt: tokens.accessPayload.exp, refreshExpiresAt: tokens.refreshPayload.exp,
    ...(identity.spaceGrant && { spaceGrant: identity.spaceGrant }) },
    accessJwt: tokens.accessJwt, refreshJwt: tokens.refreshJwt };
}

function response(issued: Issued, nonce: string): OAuthGrantResult {
  return { tag: 'ok', nonce, body: {
    access_token: issued.accessJwt, token_type: 'DPoP',
    expires_in: Math.max(0, issued.rows.accessExpiresAt - Math.floor(Date.now() / 1000)),
    refresh_token: issued.refreshJwt, scope: issued.rows.session.scope, sub: issued.rows.session.did,
  } };
}

async function failedCommit(env: Env, replay: ReplayTransaction, nonce: string): Promise<void> {
  if (await replayProofExpired(env, replay.proofIssuedAt)) throw new DpopNonceError('DPoP proof expired', nonce);
  if (await replayProofBlocked(env, replay.proofKey)) throw new DpopNonceError('DPoP proof replayed', nonce);
}

function expiredGrant(error: unknown, stage: 'auth_code' | 'refresh_token', nonce: string): OAuthGrantResult {
  if (!(error instanceof OAuthWorkerExpiry)) throw error;
  if (error.reason === 'proof') throw new DpopNonceError('DPoP proof expired', nonce);
  return invalid(stage, 'invalid_grant', 'OAuth grant expired');
}

export async function exchangeAuthorizationCode({ env, form, proof, issuer }: GrantContext): Promise<OAuthGrantResult> {
  const code = form.get('code') || '';
  const clientId = form.get('client_id') || '';
  const redirectUri = form.get('redirect_uri') || '';
  const verifier = form.get('code_verifier') || '';
  if (!code || !clientId || !redirectUri || !verifier) return invalid('auth_code', 'invalid_request', 'Missing parameters');
  const snapshot = await loadCodeSnapshot(env, code);
  const record = snapshot?.record;
  if (!snapshot || !record) return invalid('auth_code', 'invalid_grant', 'Invalid or used code');
  if (record.expiresAt <= Math.floor(Date.now() / 1000)) return invalid('auth_code', 'invalid_grant', 'Authorization code expired');
  if (record.client_id !== clientId || record.redirect_uri !== redirectUri ||
    await sha256b64url(verifier) !== record.code_challenge) return invalid('auth_code', 'invalid_grant', 'Invalid authorization code binding');
  if (proof.jkt !== record.dpopJkt) return invalid('auth_code', 'invalid_dpop', 'DPoP key mismatch');
  const space = await codeSpaceGrant(record);
  if (space.tag === 'invalid') return invalid('auth_code', 'invalid_grant', 'Invalid Space consent');
  let auth;
  try {
    auth = await requireStoredClientAuthentication(env, clientId, issuer, form, {
      method: record.clientAuthMethod, keyId: record.clientAuthKeyId, keyBinding: record.clientAuthKeyBinding,
    }, { deferReplay: true });
  } catch {
    return invalid('client_auth', 'invalid_client', 'Client authentication failed');
  }
  const issued = await issueRows(env, {
    did: record.did, clientId, method: record.clientAuthMethod, keyId: record.clientAuthKeyId ?? null,
    keyBinding: record.clientAuthKeyBinding ?? null, jkt: record.dpopJkt, scope: record.scope,
    ...(space.tag === 'valid' && { spaceGrant: space.grant }),
  });
  const nonce = await getAuthzNonce(env);
  const replay = prepareReplayTransaction(env, proof, auth.replay);
  if (!replay) throw new DpopNonceError('Invalid DPoP proof', nonce);
  try {
    await commitOAuthCodeExchange(env, snapshot, replay, issued.rows);
  } catch (error) {
    if (error instanceof OAuthWorkerExpiry) return expiredGrant(error, 'auth_code', nonce);
    await failedCommit(env, replay, nonce);
    const current = await loadCodeSnapshot(env, code);
    if (!current || current.value !== snapshot.value) return invalid('auth_code', 'invalid_grant', 'Authorization code changed');
    throw error;
  }
  try {
    ensureWorkerWindow(replay, [record.expiresAt, issued.rows.session.expiresAt, issued.rows.accessExpiresAt, issued.rows.refreshExpiresAt]);
  } catch (error) {
    return expiredGrant(error, 'auth_code', nonce);
  }
  return response(issued, nonce);
}

export async function exchangeRefreshToken({ env, form, proof, issuer }: GrantContext): Promise<OAuthGrantResult> {
  const token = form.get('refresh_token') || '';
  const clientId = form.get('client_id') || '';
  if (!token || !clientId) return invalid('refresh_token', 'invalid_request', 'Missing refresh_token or client_id');
  const verified = await verifyRefreshToken(env, token).catch(() => null);
  const payload = verified?.payload;
  const confirmation = payload?.cnf;
  const jkt = confirmation && typeof confirmation === 'object' && !Array.isArray(confirmation)
    ? (confirmation as Record<string, unknown>).jkt : null;
  if (!payload || typeof payload.jti !== 'string' || !payload.jti || typeof payload.sub !== 'string' ||
    typeof payload.exp !== 'number' || !Number.isFinite(payload.exp) ||
    typeof payload.iat !== 'number' || !Number.isFinite(payload.iat) ||
    typeof payload.client_id !== 'string' || typeof payload.oauth_session !== 'string' || typeof jkt !== 'string') {
    return invalid('refresh_token', 'invalid_grant', 'Invalid refresh token');
  }
  const snapshot = await loadOAuthRefreshSnapshot(env, payload.jti);
  if (!snapshot) return invalid('refresh_token', 'invalid_grant', 'Refresh token unavailable');
  const { refresh, session } = snapshot;
  if (proof.jkt !== session.dpopJkt) return invalid('refresh_token', 'invalid_dpop', 'DPoP key mismatch');
  if (refresh.tokenKind !== 'oauth' || session.revokedAt !== null || refresh.oauthSessionId !== session.id ||
    payload.oauth_session !== session.id || payload.sub !== session.did || refresh.did !== session.did ||
    payload.client_id !== session.clientId || clientId !== session.clientId || refresh.clientId !== session.clientId ||
    jkt !== session.dpopJkt || refresh.dpopJkt !== session.dpopJkt ||
    refresh.clientAuthMethod !== session.clientAuthMethod || refresh.clientAuthKeyId !== session.clientAuthKeyId ||
    refresh.oauthScope !== session.scope || refresh.appPasswordName !== null) {
    return invalid('refresh_token', 'invalid_grant', 'Refresh token binding mismatch');
  }
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp <= now || refresh.expiresAt <= now || session.expiresAt <= now) {
    return invalid('refresh_token', 'invalid_grant', 'Refresh token expired');
  }
  const state = refreshState(refresh, session);
  if (state.tag === 'invalid') return invalid('refresh_token', 'invalid_grant', 'Refresh token state is invalid');
  const space = await sessionSpaceGrant(env, session, payload.space_grant);
  if (space.tag === 'invalid') return invalid('refresh_token', 'invalid_grant', 'Invalid Space consent');
  if (space.tag === 'valid') {
    const requestedScopes = form.getAll('scope');
    if (requestedScopes.length > 1 || (requestedScopes.length === 1 && requestedScopes[0] !== '' && requestedScopes[0] !== session.scope)) {
      return invalid('refresh_token', 'invalid_scope', 'Space consent cannot be changed during refresh');
    }
  }
  let auth;
  try {
    auth = await requireStoredClientAuthentication(env, clientId, issuer, form, {
      method: session.clientAuthMethod, keyId: session.clientAuthKeyId, keyBinding: session.clientAuthKeyBinding,
    }, { deferReplay: true });
  } catch {
    return invalid('client_auth', 'invalid_client', 'Client authentication failed');
  }
  const issued = state.tag === 'current' ? await issueRows(env, {
    did: session.did, clientId, method: session.clientAuthMethod, keyId: session.clientAuthKeyId,
    keyBinding: session.clientAuthKeyBinding, jkt: session.dpopJkt, scope: session.scope,
    ...(space.tag === 'valid' && { spaceGrant: space.grant }),
  }, session) : null;
  const nonce = await getAuthzNonce(env);
  const replay = prepareReplayTransaction(env, proof, auth.replay);
  if (!replay) throw new DpopNonceError('Invalid DPoP proof', nonce);
  try {
    if (issued) await commitOAuthRefreshRotation(env, snapshot, replay, issued.rows, payload.exp, now,
      space.tag === 'valid' ? space.grant : undefined);
    else await commitOAuthRefreshReplay(env, snapshot, replay, payload.exp, now,
      space.tag === 'valid' ? space.grant : undefined);
  } catch (error) {
    if (error instanceof OAuthWorkerExpiry) return expiredGrant(error, 'refresh_token', nonce);
    await failedCommit(env, replay, nonce);
    const currentSnapshot = await loadOAuthRefreshSnapshot(env, refresh.id);
    if (!currentSnapshot || !equalValues(refreshSnapshotValues(currentSnapshot.refresh), refreshSnapshotValues(refresh)) ||
      !equalValues(sessionSnapshotValues(currentSnapshot.session), sessionSnapshotValues(session))) {
      return invalid('refresh_token', 'invalid_grant', 'Refresh token state changed');
    }
    if (space.tag === 'valid') {
      const currentGrant = await sessionSpaceGrant(env, currentSnapshot.session, payload.space_grant);
      if (currentGrant.tag !== 'valid' || currentGrant.grant.snapshot !== space.grant.snapshot ||
        currentGrant.grant.digest !== space.grant.digest ||
        await loadActiveSpaceIncarnation(env, session.did) !== space.grant.accountIncarnation) {
        return invalid('refresh_token', 'invalid_grant', 'Space grant state changed');
      }
    }
    throw error;
  }
  if (issued) {
    try {
      ensureWorkerWindow(replay, [refresh.expiresAt, session.expiresAt, payload.exp,
        issued.rows.session.expiresAt, issued.rows.accessExpiresAt, issued.rows.refreshExpiresAt]);
    } catch (error) {
      return expiredGrant(error, 'refresh_token', nonce);
    }
  }
  return issued ? response(issued, nonce) : invalid('refresh_token', 'invalid_grant', 'Refresh token replayed');
}

function equalValues(left: readonly (string | number | null)[], right: readonly (string | number | null)[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function refreshState(refresh: RefreshTokenRow, session: OAuthSessionRow): RefreshState {
  if (refresh.revokedAt === null && refresh.nextId === null &&
    session.currentRefreshTokenId === refresh.id && session.accessJti === refresh.accessJti) return { tag: 'current' };
  if (refresh.revokedAt !== null && refresh.nextId && session.currentRefreshTokenId !== refresh.id) return { tag: 'used' };
  return { tag: 'invalid' };
}
