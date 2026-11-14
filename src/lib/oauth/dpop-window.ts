export const DPOP_PROOF_MAX_AGE_SEC = 300;
export const DPOP_PROOF_FUTURE_SKEW_SEC = 30;

// The proof remains valid at exactly iat + max age. Replay entries expire at
// integer seconds and cleanup deletes entries whose expiry equals the clock.
export function dpopProofReplayExpiresAt(iat: number): number {
  return Math.floor(iat + DPOP_PROOF_MAX_AGE_SEC) + 1;
}

export function isDpopProofFresh(iat: number): boolean {
  const now = Math.floor(Date.now() / 1000);
  return Number.isFinite(iat) && now - iat <= DPOP_PROOF_MAX_AGE_SEC &&
    iat - now <= DPOP_PROOF_FUTURE_SKEW_SEC;
}
