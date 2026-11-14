import { isValidTid } from '@atproto/syntax-spaces';
import type { Env } from '../env';
import type { VerifiedSpacePrincipal } from '../lib/oauth/space-principal';
import type { ListSpacesTarget } from '../lib/spaces/list-spaces-request';
import { DPOP_PROOF_FUTURE_SKEW_SEC, DPOP_PROOF_MAX_AGE_SEC } from '../lib/oauth/dpop-window';
import { ASSERT_CLOCK, REFRESH_CLOCK } from './oauth-replay';
import { validLifecycleNonce } from './space-lifecycle-types';
import { ownerSpacePageSql } from './space-owner-page-sql';
import { authorizationSql, authorizationValues, windowIsLive, windowIsLiveAt } from './space-read-auth';
import { assertLocalSpaceRepo, parseSpaceRef } from './space-ref';

export type OwnerSpacePageContext = {
  readonly env: Env;
  readonly database: D1Database;
  readonly request: Request;
  readonly principal: VerifiedSpacePrincipal;
  readonly target: ListSpacesTarget;
};
export type OwnerSpacePageEntry = {
  readonly space: string;
  readonly nonce: string;
  readonly createdAt: number;
  readonly repo: null | {
    readonly revision: string;
    readonly setHash: Uint8Array;
    readonly generation: number;
    readonly mutationId: string;
    readonly epochId: string;
  };
};
export type OwnerSpacePage = { readonly entries: readonly OwnerSpacePageEntry[]; readonly cursor?: string };
type Row = {
  space_ref: unknown; creation_nonce: unknown; created_at: unknown; valid: unknown;
  repo_status: unknown; repo_rev: unknown; set_hash: unknown; generation: unknown;
  mutation_id: unknown; epoch_id: unknown; sentinel: unknown; session_expires_at: unknown; quarantined: unknown;
};

/** Read a page in one primary-D1 transaction behind the current session and grant. */
export async function selectOwnerSpacePage(context: OwnerSpacePageContext): Promise<OwnerSpacePage | null> {
  const { env, database, request, principal, target } = context;
  if (request.signal.aborted || env.ALTERAN_DB !== database || !windowIsLive(principal)) return null;
  await assertLocalSpaceRepo(env, principal.did);
  if (request.signal.aborted || env.ALTERAN_DB !== database || !windowIsLive(principal)) return null;
  const now = Math.floor(Date.now() / 1000);
  if (!Number.isSafeInteger(now) || now < 0) return null;
  const nonce = crypto.randomUUID().replaceAll('-', '');
  const values = [target.authorityDid, principal.grant.accountIncarnation, target.spaceType,
    ...(target.cursor === null ? [] : [target.cursor]), target.authorityDid, target.spaceType, target.limit,
    target.authorityDid, target.spaceType];
  const rows = await database.batch([
    database.prepare(`UPDATE oauth_replay_clock SET seconds = MAX(seconds, unixepoch(), ?), nonce = ?
      WHERE id = 1 AND typeof(seconds) = 'integer' AND seconds BETWEEN 0 AND 9007199254740991`).bind(now, nonce),
    database.prepare(ASSERT_CLOCK).bind(nonce),
    database.prepare(ownerSpacePageSql(target.cursor !== null)).bind(...authorizationValues(principal, nonce), ...values),
    database.prepare(REFRESH_CLOCK).bind(nonce),
    database.prepare(ASSERT_CLOCK).bind(nonce),
    database.prepare(`${authorizationSql('nonce')}
      SELECT clock.seconds, (SELECT session_expires_at FROM authorized) AS session_expires_at FROM clock`)
      .bind(...authorizationValues(principal, nonce)),
  ]);
  if (!Array.isArray(rows) || rows.length !== 6 || rows.some((entry) => entry?.success !== true) ||
    !assertionPassed(rows[1]?.results) || !assertionPassed(rows[4]?.results) || !windowIsLive(principal)) return null;
  const finalRows = rows[5]?.results;
  if (!Array.isArray(finalRows) || finalRows.length !== 1 || !finalRows[0] ||
    typeof finalRows[0] !== 'object' || Array.isArray(finalRows[0])) return null;
  const final = finalRows[0] as Record<string, unknown>;
  const clock = final.seconds, expiry = final.session_expires_at;
  if (typeof clock !== 'number' || !Number.isSafeInteger(clock) || clock < now || principal.expiresAt <= clock ||
    clock - principal.proofIssuedAt > DPOP_PROOF_MAX_AGE_SEC ||
    principal.proofIssuedAt - clock > DPOP_PROOF_FUTURE_SKEW_SEC ||
    typeof expiry !== 'number' || !Number.isSafeInteger(expiry) || expiry <= clock) return null;
  const selected = rows[2]?.results;
  if (!Array.isArray(selected) || selected.length > target.limit + 1 ||
    selected.some((row) => !row || typeof row !== 'object' || Array.isArray(row))) return null;
  const typed = selected as Row[];
  const sentinels = typed.filter((row) => row.sentinel === 1);
  const records = typed.filter((row) => row.sentinel === 0);
  if (sentinels.length !== 1 || records.length > target.limit || sentinels.length + records.length !== typed.length ||
    sentinels[0].session_expires_at !== expiry || sentinels[0].quarantined !== 0 ||
    records.some((row) => row.session_expires_at !== null || row.quarantined !== null)) return null;
  let entries: OwnerSpacePageEntry[];
  try {
    entries = records.map((row) => decodeEntry(row, target));
    entries.sort((left, right) => left.space < right.space ? -1 : left.space > right.space ? 1 : 0);
    let previous = target.cursor;
    for (const entry of entries) {
      if (previous !== null && previous >= entry.space) return null;
      previous = entry.space;
    }
  } catch {
    return null;
  }
  await assertLocalSpaceRepo(env, principal.did);
  const after = Math.floor(Date.now() / 1000);
  if (request.signal.aborted || env.ALTERAN_DB !== database || !windowIsLiveAt(principal, after) || expiry <= after) return null;
  const last = entries.at(-1);
  return { entries, ...(entries.length === target.limit && last ? { cursor: last.space } : {}) };
}

function decodeEntry(row: Row, target: ListSpacesTarget): OwnerSpacePageEntry {
  if (row.valid !== 1 || typeof row.space_ref !== 'string' || !validLifecycleNonce(row.creation_nonce) ||
    typeof row.created_at !== 'number' || !Number.isSafeInteger(row.created_at) || row.created_at < 0) throw new Error();
  const reference = parseSpaceRef(row.space_ref);
  if (reference.authorityDid !== target.authorityDid || reference.spaceType !== target.spaceType) throw new Error();
  if (row.repo_status === 0) {
    if (row.repo_rev !== null || row.set_hash !== null || row.generation !== null ||
      row.mutation_id !== null || row.epoch_id !== null) throw new Error();
    return { space: reference.ref, nonce: row.creation_nonce, createdAt: row.created_at, repo: null };
  }
  if (row.repo_status !== 1 || !isValidTid(row.repo_rev) || !validLifecycleNonce(row.mutation_id) ||
    typeof row.generation !== 'number' || !Number.isSafeInteger(row.generation) || row.generation < 1 ||
    typeof row.epoch_id !== 'string' || !row.epoch_id || new TextEncoder().encode(row.epoch_id).byteLength > 128 ||
    !Array.isArray(row.set_hash) || row.set_hash.length !== 2048) throw new Error();
  const bytes = new Uint8Array(2048);
  for (let index = 0; index < bytes.length; index++) {
    const byte: unknown = row.set_hash[index];
    if (!Object.hasOwn(row.set_hash, index) || typeof byte !== 'number' || !Number.isInteger(byte) || byte < 0 || byte > 255) {
      throw new Error();
    }
    bytes[index] = byte;
  }
  return { space: reference.ref, nonce: row.creation_nonce, createdAt: row.created_at, repo: {
    revision: row.repo_rev, setHash: bytes, generation: row.generation, mutationId: row.mutation_id, epochId: row.epoch_id,
  } };
}

function assertionPassed(rows: unknown): boolean {
  return Array.isArray(rows) && rows.length === 1 && rows[0]?.valid === 1;
}
