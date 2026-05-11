/**
 * Refresh-session validation as a small, total state machine.
 *
 * The XRPC handler used to be ~100 lines of linear guards that each
 * returned a different Response shape. Lifting the checks into one
 * function that returns a discriminated `RefreshOutcome` lets the
 * handler reduce to a single switch, and lets us unit-test every
 * decision branch without an HTTP layer.
 */
import type { Env } from '../env';
import { InvalidToken } from './errors';
import { getRuntimeString } from './secrets';
import {
  getAccountByIdentifier,
  getRefreshToken,
  markRefreshTokenRotated,
  storeRefreshToken,
  type RefreshTokenRow,
} from '../db/account';
import {
  verifyRefreshToken,
  issueSessionTokens,
  computeGraceExpiry,
} from './session-tokens';

export type RefreshFailureCode =
  | 'AuthRequired'
  | 'InvalidToken'
  | 'ExpiredToken';

export type RefreshFailure = {
  readonly tag: 'failure';
  readonly code: RefreshFailureCode;
  readonly message: string;
  readonly status: number;
};

export type RefreshSuccess = {
  readonly tag: 'success';
  readonly did: string;
  readonly handle: string;
  readonly accessJwt: string;
  readonly refreshJwt: string;
};

export type RefreshOutcome = RefreshFailure | RefreshSuccess;

function failure(code: RefreshFailureCode, message: string, status = 401): RefreshFailure {
  return { tag: 'failure', code, message, status };
}

type AttemptInput = {
  readonly env: Env;
  readonly token: string | null;
  readonly nowSec: number;
};

/**
 * Pure-ish coordinator: every branch either fails fast or yields a
 * concrete RefreshSuccess. The handler stays thin and the test surface
 * is the return value rather than HTTP response shape.
 */
export async function attemptRefresh({ env, token, nowSec }: AttemptInput): Promise<RefreshOutcome> {
  if (!token) {
    return failure('AuthRequired', 'No authorization token provided');
  }

  // Catch only token-shape failures here; configuration errors must propagate
  // so they surface as 5xx instead of being masked as a 401.
  let verification: Awaited<ReturnType<typeof verifyRefreshToken>> | null;
  try {
    verification = await verifyRefreshToken(env, token);
  } catch (error) {
    if (error instanceof InvalidToken) {
      verification = null;
    } else {
      throw error;
    }
  }
  if (!verification) {
    return failure('InvalidToken', 'Invalid or expired refresh token');
  }

  const { decoded } = verification;
  if (
    !decoded ||
    typeof decoded.jti !== 'string' ||
    typeof decoded.sub !== 'string'
  ) {
    return failure('InvalidToken', 'Malformed refresh token');
  }

  if (typeof decoded.exp !== 'number' || decoded.exp <= nowSec) {
    return failure('ExpiredToken', 'Refresh token expired');
  }

  const stored = await getRefreshToken(env, decoded.jti);
  if (!stored) {
    return failure('InvalidToken', 'Refresh token has been revoked');
  }

  if (stored.expiresAt <= nowSec) {
    return failure('ExpiredToken', 'Refresh token expired');
  }

  if (stored.did !== decoded.sub) {
    return failure('InvalidToken', 'Token subject mismatch');
  }

  return finalizeRotation({ env, stored, expiredJti: decoded.jti, nowSec });
}

type FinalizeInput = {
  readonly env: Env;
  readonly stored: RefreshTokenRow;
  readonly expiredJti: string;
  readonly nowSec: number;
};

async function finalizeRotation({
  env,
  stored,
  expiredJti,
  nowSec,
}: FinalizeInput): Promise<RefreshOutcome> {
  const account = await getAccountByIdentifier(env, stored.did);
  const did = stored.did;
  const handle =
    account?.handle ?? (await getRuntimeString(env, 'PDS_HANDLE', 'user.example')) ?? 'user.example';

  // If a previous rotation already chose the next JTI we MUST reuse it so
  // a client retrying inside the grace window receives the same pair.
  const desiredJti = stored.nextId ?? undefined;

  const { accessJwt, refreshJwt, refreshPayload, refreshExpiry } = await issueSessionTokens(
    env,
    did,
    { jti: desiredJti },
  );

  // Reuse attack detection: the stored nextId fixes what the client is
  // allowed to see; any divergence means the same refresh was already used
  // to mint a *different* successor and this attempt is poisoned.
  if (stored.nextId && stored.nextId !== refreshPayload.jti) {
    return failure('InvalidToken', 'Refresh token has been revoked');
  }

  if (!stored.nextId) {
    await storeRefreshToken(env, {
      id: refreshPayload.jti,
      did,
      expiresAt: refreshExpiry,
      appPasswordName: stored.appPasswordName ?? null,
    });

    const graceExpiry = computeGraceExpiry(stored.expiresAt, nowSec);
    await markRefreshTokenRotated(env, expiredJti, refreshPayload.jti, graceExpiry);
  }

  return { tag: 'success', did, handle, accessJwt, refreshJwt };
}
