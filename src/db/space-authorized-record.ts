import { MAX_RECORD_SIZE } from '@atproto/space';
import { isValidNsid, isValidRecordKey } from '@atproto/syntax-spaces';
import type { Env } from '../env';
import { DPOP_PROOF_FUTURE_SKEW_SEC, DPOP_PROOF_MAX_AGE_SEC } from '../lib/oauth/dpop-window';
import type { VerifiedSpacePrincipal } from '../lib/oauth/space-principal';
import { parseSpaceRef } from './space-ref';
import { authorizationSql, authorizationValues, authorizeSpaceRead, completion, consumeSpaceRead,
  windowIsLive, windowIsLiveAt } from './space-read-auth';
import { ASSERT_CLOCK, REFRESH_CLOCK } from './oauth-replay';
import { decodeSpaceRecord, SPACE_RECORD_COLUMNS, SPACE_RECORD_TABLES,
  type SpaceRecordRow, type StoredSpaceRecord } from './space-record-projection';
import { SpaceStorageError } from './space-types';

type CompleteRead = (request: Request, database: D1Database) => Promise<boolean>;

export type AuthorizedSpaceRecordResult =
  | { readonly tag: 'found'; readonly record: StoredSpaceRecord; readonly complete: CompleteRead }
  | { readonly tag: 'notFound'; readonly complete: CompleteRead }
  | { readonly tag: 'invalid'; readonly complete: CompleteRead }
  | { readonly tag: 'unauthorized' };

type SelectedRow = SpaceRecordRow & {
  readonly sentinel: number;
  readonly session_expires_at: number | null;
  readonly epoch_id: string | null;
};

/** Read private data only while the exact verified grant and account remain live. */
export async function readAuthorizedSpaceRecord(
  env: Env,
  principal: VerifiedSpacePrincipal,
  request: Request,
  space: string,
  repo: string,
  collection: string,
  rkey: string,
): Promise<AuthorizedSpaceRecordResult> {
  const db = env.ALTERAN_DB;
  const readHandle = consumeSpaceRead(env, principal, request, db);
  if (!readHandle ||
    !matchesRequest(request, space, repo, collection, rkey) || !windowIsLive(principal)) {
    return { tag: 'unauthorized' };
  }
  const ref = parseSpaceRef(space);
  if (!isValidNsid(collection) || !isValidRecordKey(rkey)) {
    throw new SpaceStorageError('InvalidRequest', 'Invalid collection or record key');
  }
  if (!await authorizeSpaceRead(readHandle, 'getRecord', space, repo) || env.ALTERAN_DB !== db) {
    return { tag: 'unauthorized' };
  }
  const now = Math.floor(Date.now() / 1000);
  if (!Number.isSafeInteger(now) || now < 0) return { tag: 'unauthorized' };
  const nonce = crypto.randomUUID().replaceAll('-', '');
  const authorization = authorizationSql('nonce');
  const authValues = authorizationValues(principal, nonce);
  const activeEpoch = `SELECT CASE WHEN typeof(e.id) = 'text' AND length(CAST(e.id AS BLOB)) BETWEEN 1 AND 128
      THEN e.id END FROM space s JOIN space_repo h ON h.space_ref = s.space_ref AND h.repo_did = ?
      JOIN space_owned_epoch e ON e.id = h.active_epoch_id AND e.space_ref = h.space_ref
        AND e.repo_did = h.repo_did AND e.state = 'active'
      WHERE s.space_ref = ? AND s.authority_did = ? AND s.space_type = ? AND s.skey = ?
        AND s.deleted_at IS NULL AND e.owner_incarnation = ?`;
  const epochValues = [repo, ref.ref, ref.authorityDid, ref.spaceType, ref.skey, principal.grant.accountIncarnation];
  const result = await (async () => {
    const read = db.prepare(`${authorization}
      SELECT ${SPACE_RECORD_COLUMNS}, 0 AS sentinel, NULL AS session_expires_at,
        CASE WHEN typeof(e.id) = 'text' AND length(CAST(e.id AS BLOB)) BETWEEN 1 AND 128
          THEN e.id END AS epoch_id ${SPACE_RECORD_TABLES}
      WHERE record.space_ref = ? AND record.repo_did = ? AND record.collection = ? AND record.rkey = ?
        AND space.authority_did = ? AND space.space_type = ? AND space.skey = ?
        AND EXISTS (SELECT 1 FROM authorized)
        AND EXISTS (SELECT 1 FROM space_owned_epoch owned WHERE owned.id = e.id AND owned.space_ref = e.space_ref
          AND owned.repo_did = e.repo_did AND owned.owner_incarnation = ?)
      UNION ALL SELECT NULL, NULL, NULL, NULL, 0, 1, session_expires_at, (${activeEpoch}) FROM authorized`)
      .bind(...authValues, MAX_RECORD_SIZE, MAX_RECORD_SIZE,
        ref.ref, repo, collection, rkey, ref.authorityDid, ref.spaceType, ref.skey,
        principal.grant.accountIncarnation, ...epochValues);
    return db.batch([
      db.prepare(`UPDATE oauth_replay_clock SET seconds = MAX(seconds, unixepoch(), ?), nonce = ?
        WHERE id = 1 AND typeof(seconds) = 'integer' AND seconds BETWEEN 0 AND 9007199254740991`).bind(now, nonce),
      db.prepare(ASSERT_CLOCK).bind(nonce),
      read,
      db.prepare(REFRESH_CLOCK).bind(nonce),
      db.prepare(ASSERT_CLOCK).bind(nonce),
      db.prepare(`${authorization}
        SELECT clock.seconds, (SELECT session_expires_at FROM authorized) AS session_expires_at,
          EXISTS (SELECT 1 FROM space s JOIN space_repo h ON h.space_ref = s.space_ref AND h.repo_did = ?
            JOIN space_owned_epoch e ON e.id = h.active_epoch_id AND e.space_ref = h.space_ref
              AND e.repo_did = h.repo_did AND e.state = 'active'
            WHERE s.space_ref = ? AND s.authority_did = ? AND s.space_type = ? AND s.skey = ?
              AND s.deleted_at IS NULL AND e.owner_incarnation = ?) AS space_active,
          (${activeEpoch}) AS epoch_id FROM clock`)
        .bind(...authValues, repo, ref.ref, ref.authorityDid, ref.spaceType, ref.skey, principal.grant.accountIncarnation,
          ...epochValues),
    ]);
  })().catch(() => null);
  if (!Array.isArray(result) || result.length !== 6 || result.some((entry: { success?: unknown } | null) => entry?.success !== true) ||
    !clockAssertionPassed(result[1]?.results) || !clockAssertionPassed(result[4]?.results)) {
    return { tag: 'unauthorized' };
  }
  if (env.ALTERAN_DB !== db || !windowIsLive(principal)) return { tag: 'unauthorized' };
  const finalRows = result[5]?.results;
  if (!Array.isArray(finalRows) || finalRows.length !== 1) return { tag: 'unauthorized' };
  const final = finalRows[0];
  if (!final || typeof final !== 'object') return { tag: 'unauthorized' };
  const clock = final.seconds;
  if (typeof clock !== 'number' || !Number.isSafeInteger(clock) || clock < now ||
    principal.expiresAt <= clock || clock - principal.proofIssuedAt > DPOP_PROOF_MAX_AGE_SEC ||
    principal.proofIssuedAt - clock > DPOP_PROOF_FUTURE_SKEW_SEC) return { tag: 'unauthorized' };
  const selected = result[2]?.results;
  if (!Array.isArray(selected) || selected.length > 2 ||
    selected.some((row) => !row || typeof row !== 'object')) return { tag: 'unauthorized' };
  const rows = selected as SelectedRow[];
  const sentinels = rows.filter((row) => row.sentinel === 1);
  const records = rows.filter((row) => row.sentinel === 0);
  if (sentinels.length !== 1 || records.length > 1 || sentinels.length + records.length !== rows.length) {
    return { tag: 'unauthorized' };
  }
  const sessionExpiresAt = final.session_expires_at;
  if (typeof sessionExpiresAt !== 'number' || !Number.isSafeInteger(sessionExpiresAt) || sessionExpiresAt <= clock ||
    final.space_active !== 1 || sentinels[0].session_expires_at !== sessionExpiresAt ||
    sentinels[0].cid !== null || sentinels[0].value_cbor !== null || sentinels[0].repo_rev !== null ||
    sentinels[0].head_rev !== null || sentinels[0].consistent !== 0 ||
    records.some((row) => row.session_expires_at !== null)) {
    return { tag: 'unauthorized' };
  }
  const epoch = final.epoch_id;
  if (typeof epoch !== 'string' || epoch.length < 1 || epoch.length > 128 ||
    new TextEncoder().encode(epoch).byteLength > 128 || sentinels[0].epoch_id !== epoch ||
    records.some((row) => row.epoch_id !== epoch)) {
    return { tag: 'unauthorized' };
  }
  let record: StoredSpaceRecord | null = null;
  let invalid = false;
  try {
    if (records.length) record = decodeSpaceRecord(records[0], collection);
  } catch {
    invalid = true;
  }
  const after = Math.floor(Date.now() / 1000);
  if (request.signal.aborted || !windowIsLiveAt(principal, after) || sessionExpiresAt <= after) {
    return { tag: 'unauthorized' };
  }
  const complete = completion(readHandle, epoch);
  if (invalid) return Object.freeze({ tag: 'invalid', complete });
  return record ? Object.freeze({ tag: 'found', record, complete }) : Object.freeze({ tag: 'notFound', complete });
}

function clockAssertionPassed(rows: unknown): boolean {
  return Array.isArray(rows) && rows.length === 1 && rows[0]?.valid === 1;
}

function matchesRequest(request: Request, space: string, repo: string, collection: string, rkey: string): boolean {
  if (request.signal.aborted || request.method !== 'GET') return false;
  const url = new URL(request.url);
  return url.pathname === '/xrpc/com.atproto.space.getRecord' &&
    Array.from(url.searchParams.keys()).every((key) => ['space', 'repo', 'collection', 'rkey'].includes(key)) &&
    Object.entries({ space, repo, collection, rkey }).every(([key, expected]) => {
      const values = url.searchParams.getAll(key);
      return values.length === 1 && values[0] === expected;
    });
}
