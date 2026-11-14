import type { Env } from '../env';
import { SPACE_GENESIS_EMPTY } from './space-genesis-sql';
import { SPACE_AVAILABLE } from './space-mutation-sql';
import type { SpaceOwner } from './space-owner';
import { SpaceStorageError, type SpaceRef } from './space-types';

export async function classifySpaceMutationConflict(
  env: Env,
  ref: SpaceRef,
  owner: SpaceOwner,
): Promise<{ readonly tag: 'conflict' | 'missingSpace' }> {
  const repoDid = owner.did;
  const spaceStatus = await env.ALTERAN_DB.prepare(`WITH t AS MATERIALIZED (
      SELECT ? AS space_ref, ? AS repo_did, ? AS owner_incarnation
    ) SELECT ${SPACE_AVAILABLE} AS ok FROM t
    JOIN account a ON a.did = t.repo_did AND a.space_incarnation = t.owner_incarnation
    JOIN account_state state ON state.did = a.did AND typeof(state.active) = 'integer' AND state.active = 1
      AND state.status IS NULL AND state.suspended_until IS NULL
    WHERE NOT EXISTS (SELECT 1 FROM space s WHERE s.space_ref = t.space_ref
      AND (s.space_ref != 'at://' || s.authority_did || '/space/' || s.space_type || '/' || s.skey
        OR (s.authority_did = t.repo_did AND NOT EXISTS (SELECT 1 FROM space_personal_policy p
          WHERE p.space_ref = s.space_ref AND p.authority_did = t.repo_did AND p.authority_incarnation = t.owner_incarnation))))
      AND (EXISTS (SELECT 1 FROM space_repo h JOIN space_owned_epoch e ON e.id = h.active_epoch_id
          AND e.space_ref = h.space_ref AND e.repo_did = h.repo_did AND e.state = 'active'
        WHERE h.space_ref = t.space_ref AND h.repo_did = t.repo_did AND e.owner_incarnation = t.owner_incarnation)
        OR (${SPACE_GENESIS_EMPTY}))`)
    .bind(ref.ref, repoDid, owner.incarnation, ref.ref, ref.authorityDid, repoDid, ref.ref)
    .first<{ ok: number }>();
  if (!spaceStatus) throw new SpaceStorageError('SpaceEpochUnavailable', 'Space owner is unavailable');
  if (!spaceStatus.ok) return { tag: 'missingSpace' };
  return { tag: 'conflict' };
}
