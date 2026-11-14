import { SPACE_GENESIS_EMPTY } from './space-genesis-sql';
import type { SpaceRef } from './space-types';

// This witness is only useful for a personal Space owned by its local repo.
// Callers must evaluate it behind the authorized session and recheck it when
// completing the response. A future delete/recreate implementation must bind
// this identity to a fresh generation and fence all earlier cleanup and writes.
export const SPACE_PERSONAL_GENESIS = `SELECT p.creation_nonce, p.created_at
  FROM (SELECT ? AS space_ref, ? AS repo_did) t
  CROSS JOIN space s CROSS JOIN space_personal_policy p
  WHERE s.space_ref = t.space_ref AND p.space_ref = t.space_ref
    AND typeof(s.authority_did) = 'text' AND s.authority_did = ?
    AND typeof(s.space_type) = 'text' AND s.space_type = ?
    AND typeof(s.skey) = 'text' AND s.skey = ? AND s.deleted_at IS NULL
    AND typeof(p.authority_did) = 'text' AND p.authority_did = ?
    AND typeof(p.authority_incarnation) = 'text' AND p.authority_incarnation = ?
    AND typeof(p.policy_type) = 'text' AND p.policy_type = 'com.atproto.personalspace.policy'
    AND typeof(p.notification_state) = 'text' AND p.notification_state = 'none'
    AND typeof(p.creation_nonce) = 'text' AND length(CAST(p.creation_nonce AS BLOB)) = 36
    AND typeof(p.created_at) = 'integer' AND p.created_at BETWEEN 0 AND 9007199254740991
    AND typeof(s.created_at) = 'integer' AND s.created_at = p.created_at
    AND (${SPACE_GENESIS_EMPTY})`;

export function personalGenesisValues(ref: SpaceRef, repo: string, incarnation: string) {
  return [ref.ref, repo, ref.authorityDid, ref.spaceType, ref.skey, repo, incarnation];
}
