import type { Env } from '../env';
import { isSpaceDid } from '../lib/spaces/space-did';
import { isSpaceOwnerIncarnation } from './space-owner-incarnation';
import { SpaceStorageError } from './space-types';

/** The caller must obtain this value from a trusted account or verified request. */
export type SpaceOwner = Readonly<{ did: string; incarnation: string }>;

export function captureSpaceOwner(did: unknown, incarnation: unknown): SpaceOwner {
  if (!isSpaceDid(did) || !isSpaceOwnerIncarnation(incarnation)) {
    throw new SpaceStorageError('NotAuthorized', 'Space owner is unavailable');
  }
  return Object.freeze({ did, incarnation });
}

/** Test and trusted maintenance callers may capture the current active owner once. */
export async function loadActiveSpaceOwner(env: Env, did: string): Promise<SpaceOwner | null> {
  if (!isSpaceDid(did)) return null;
  const row = await env.ALTERAN_DB.prepare(`SELECT CASE WHEN typeof(a.space_incarnation) = 'text'
      AND length(a.space_incarnation) = 32 AND length(CAST(a.space_incarnation AS BLOB)) = 32
      AND a.space_incarnation NOT GLOB '*[^0-9a-f]*' THEN a.space_incarnation END AS incarnation
    FROM account a JOIN account_state state ON state.did = a.did
    WHERE a.did = ? AND typeof(state.active) = 'integer' AND state.active = 1
      AND state.status IS NULL AND state.suspended_until IS NULL`)
    .bind(did).first<{ incarnation: string | null }>();
  return isSpaceOwnerIncarnation(row?.incarnation) ? captureSpaceOwner(did, row.incarnation) : null;
}
