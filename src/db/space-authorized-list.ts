import { MAX_RECORD_SIZE } from '@atproto/space';
import { isValidNsid, isValidRecordKey, isValidTid } from '@atproto/syntax-spaces';
import type { Env } from '../env';
import { DPOP_PROOF_FUTURE_SKEW_SEC, DPOP_PROOF_MAX_AGE_SEC } from '../lib/oauth/dpop-window';
import type { VerifiedSpacePrincipal } from '../lib/oauth/space-principal';
import { parseSpaceListRequest } from '../lib/spaces/list-records-request';
import { inspectRecordCborBounds, MAX_RECORD_CBOR_ITEMS } from '../lib/spaces/record-cbor-bounds';
import { captureRecordIdentity } from '../lib/spaces/record-response-input';
import { parseCanonicalRepoCid } from '../lib/spaces/repo-cid';
import { ASSERT_CLOCK, REFRESH_CLOCK } from './oauth-replay';
import { parseSpaceRef } from './space-ref';
import { SpaceStorageError } from './space-types';
import { validLifecycleNonce } from './space-lifecycle-types';
import { personalGenesisValues, SPACE_PERSONAL_GENESIS } from './space-personal-genesis-sql';
import { decodeSpaceRecord, type SpaceRecordRow, type StoredSpaceRecord } from './space-record-projection';
import { authorizationSql, authorizationValues, authorizeSpaceRead, completion, consumeSpaceRead, genesisListCompletion,
  windowIsLive, windowIsLiveAt } from './space-read-auth';

type CompleteRead = (request: Request, database: D1Database) => Promise<boolean>;
export type ListedSpaceRecord = {
  readonly collection: string; readonly rkey: string; readonly cid: string; readonly record?: StoredSpaceRecord;
};
export type AuthorizedSpaceListResult =
  | { readonly tag: 'found'; readonly records: readonly ListedSpaceRecord[]; readonly cursor?: string; readonly complete: CompleteRead }
  | { readonly tag: 'tooLarge'; readonly complete: CompleteRead }
  | { readonly tag: 'invalid'; readonly complete: CompleteRead }
  | { readonly tag: 'unauthorized' };

type ListRow = {
  collection: unknown; rkey: unknown; cid: unknown; repo_rev: unknown; head_rev: unknown;
  consistent: unknown; epoch_id: unknown; sentinel: unknown; session_expires_at: unknown; too_large: unknown;
  budget_total: unknown; genesis_nonce: unknown; genesis_created_at: unknown; value_cbor?: unknown;
};
const MAX_PAGE_COMPARE_BYTES = 4 * 1024 * 1024;
const MAX_PAGE_VALUE_BYTES = MAX_RECORD_SIZE;

/** Read bounded record pages under the exact verified Space grant. */
export async function listAuthorizedSpaceRecords(
  env: Env, principal: VerifiedSpacePrincipal, request: Request,
): Promise<AuthorizedSpaceListResult> {
  const db = env.ALTERAN_DB;
  const handle = consumeSpaceRead(env, principal, request, db);
  const parsed = parseSpaceListRequest(request);
  if (!handle || parsed.tag !== 'valid' || !windowIsLive(principal)) return { tag: 'unauthorized' };
  const target = parsed.target;
  const ref = parseSpaceRef(target.space);
  if (!await authorizeSpaceRead(handle, 'listRecords', target.space, target.repo) || env.ALTERAN_DB !== db) {
    return { tag: 'unauthorized' };
  }
  const now = Math.floor(Date.now() / 1000);
  if (!Number.isSafeInteger(now) || now < 0) return { tag: 'unauthorized' };
  const nonce = crypto.randomUUID().replaceAll('-', '');
  const authorization = authorizationSql('nonce');
  const authValues = authorizationValues(principal, nonce);
  const maxPageBytes = target.excludeValues ? MAX_PAGE_COMPARE_BYTES : MAX_PAGE_VALUE_BYTES;
  const valueProjection = target.excludeValues ? '' : `, CASE WHEN budget.total <= ${MAX_PAGE_VALUE_BYTES}
    AND typeof(record.value_cbor) = 'blob' AND length(record.value_cbor) BETWEEN 1 AND ${MAX_RECORD_SIZE}
    THEN record.value_cbor END AS value_cbor`;
  const valueSentinel = target.excludeValues ? '' : ', NULL';
  const activeEpoch = `SELECT CASE WHEN typeof(e.id) = 'text' AND length(CAST(e.id AS BLOB)) BETWEEN 1 AND 128
      THEN e.id END FROM space s JOIN space_repo h ON h.space_ref = s.space_ref AND h.repo_did = ?
      JOIN space_owned_epoch e ON e.id = h.active_epoch_id AND e.space_ref = h.space_ref
        AND e.repo_did = h.repo_did AND e.state = 'active'
      WHERE s.space_ref = ? AND s.authority_did = ? AND s.space_type = ? AND s.skey = ?
        AND s.deleted_at IS NULL AND e.owner_incarnation = ?`;
  const epochValues = [target.repo, ref.ref, ref.authorityDid, ref.spaceType, ref.skey, principal.grant.accountIncarnation];
  const personal = ref.authorityDid === principal.did && target.repo === principal.did;
  const genesis = personal
    ? `genesis AS MATERIALIZED (SELECT candidate.creation_nonce, candidate.created_at
        FROM authorized CROSS JOIN (${SPACE_PERSONAL_GENESIS}) candidate)`
    : `genesis AS MATERIALIZED (SELECT NULL AS creation_nonce, NULL AS created_at WHERE 0)`;
  const genesisValues = personal ? personalGenesisValues(ref, target.repo, principal.grant.accountIncarnation) : [];
  const path = `(record.collection || '/' || record.rkey) COLLATE BINARY`;
  const filter: string[] = [];
  const filters: (string | number)[] = [];
  if (target.collection !== null) {
    const collectionUpper = `${target.collection}0`;
    const upper = target.cursorPath !== null && target.cursorPath < collectionUpper
      ? target.cursorPath : collectionUpper;
    filter.push(`${path} >= ? COLLATE BINARY`, `${path} < ? COLLATE BINARY`);
    filters.push(`${target.collection}/`, upper);
  } else if (target.cursorPath !== null) {
    filter.push(`${path} < ? COLLATE BINARY`);
    filters.push(target.cursorPath);
  }
  const result = await (async () => {
    const page = db.prepare(`${authorization}, ${genesis}, candidates AS MATERIALIZED (
      SELECT record.rowid AS record_id,
        CASE WHEN typeof(record.value_cbor) = 'blob' AND length(record.value_cbor) BETWEEN 1 AND ?
          THEN length(record.value_cbor) ELSE ? END AS value_size
      FROM space_record record INDEXED BY space_record_path_idx
        JOIN space s ON s.space_ref = record.space_ref AND s.deleted_at IS NULL
        JOIN space_repo h ON h.space_ref = record.space_ref AND h.repo_did = record.repo_did
        JOIN space_owned_epoch e ON e.id = h.active_epoch_id AND e.space_ref = h.space_ref
          AND e.repo_did = h.repo_did AND e.state = 'active'
      WHERE record.space_ref = ? AND record.repo_did = ? AND s.authority_did = ? AND s.space_type = ? AND s.skey = ?
        AND e.owner_incarnation = ? AND EXISTS (SELECT 1 FROM authorized)
        ${filter.length ? `AND ${filter.join(' AND ')}` : ''}
      ORDER BY ${path} DESC LIMIT ?
    ), budget AS MATERIALIZED (SELECT COALESCE(SUM(value_size), 0) AS total FROM candidates),
    page AS MATERIALIZED (
      SELECT CASE WHEN typeof(record.collection) = 'text' AND length(CAST(record.collection AS BLOB)) BETWEEN 1 AND 317
          THEN record.collection END AS collection,
        CASE WHEN typeof(record.rkey) = 'text' AND length(CAST(record.rkey AS BLOB)) BETWEEN 1 AND 512 THEN record.rkey END AS rkey,
        CASE WHEN typeof(record.cid) = 'text' AND length(CAST(record.cid AS BLOB)) BETWEEN 1 AND 128 THEN record.cid END AS cid,
        CASE WHEN typeof(record.repo_rev) = 'text' AND length(CAST(record.repo_rev AS BLOB)) = 13 THEN record.repo_rev END AS repo_rev,
        CASE WHEN typeof(h.rev) = 'text' AND length(CAST(h.rev AS BLOB)) = 13 THEN h.rev END AS head_rev,
        CASE WHEN budget.total > ${MAX_PAGE_COMPARE_BYTES} THEN 0
          WHEN typeof(record.value_cbor) = 'blob' AND length(record.value_cbor) BETWEEN 1 AND ?
            AND typeof(v.value_cbor) = 'blob' AND length(v.value_cbor) = length(record.value_cbor)
            AND typeof(record.cid) = 'text' AND length(CAST(record.cid AS BLOB)) BETWEEN 1 AND 128
            AND typeof(v.cid) = 'text' AND length(CAST(v.cid AS BLOB)) BETWEEN 1 AND 128
            AND typeof(record.repo_rev) = 'text' AND length(CAST(record.repo_rev AS BLOB)) = 13
            AND typeof(v.repo_rev) = 'text' AND length(CAST(v.repo_rev AS BLOB)) = 13
            AND typeof(record.collection) = 'text' AND length(CAST(record.collection AS BLOB)) BETWEEN 1 AND 317
            AND typeof(v.collection) = 'text' AND length(CAST(v.collection AS BLOB)) BETWEEN 1 AND 317
            AND typeof(record.rkey) = 'text' AND length(CAST(record.rkey AS BLOB)) BETWEEN 1 AND 512
            AND typeof(v.rkey) = 'text' AND length(CAST(v.rkey AS BLOB)) BETWEEN 1 AND 512
          THEN CASE WHEN v.value_cbor IS record.value_cbor
            AND v.cid IS record.cid AND v.repo_rev IS record.repo_rev AND v.value_size = length(record.value_cbor)
            AND v.collection IS record.collection AND v.rkey IS record.rkey
            AND typeof(h.generation) = 'integer' AND h.generation BETWEEN 1 AND 9007199254740991
            AND typeof(v.from_generation) = 'integer' AND v.from_generation BETWEEN 1 AND h.generation
            THEN 1 ELSE 0 END ELSE 0 END AS consistent,
        CASE WHEN typeof(e.id) = 'text' AND length(CAST(e.id AS BLOB)) BETWEEN 1 AND 128 THEN e.id END AS epoch_id,
        0 AS sentinel, NULL AS session_expires_at, 0 AS too_large, 0 AS budget_total,
        NULL AS genesis_nonce, NULL AS genesis_created_at${valueProjection}
      FROM candidates candidate CROSS JOIN budget CROSS JOIN space_record record NOT INDEXED
        JOIN space s ON s.space_ref = record.space_ref AND s.deleted_at IS NULL
        JOIN space_repo h ON h.space_ref = record.space_ref AND h.repo_did = record.repo_did
        JOIN space_owned_epoch e ON e.id = h.active_epoch_id AND e.space_ref = h.space_ref
          AND e.repo_did = h.repo_did AND e.state = 'active'
        LEFT JOIN space_record_version v ON v.epoch_id = e.id AND v.space_ref = record.space_ref
          AND v.repo_did = record.repo_did AND v.path = CASE
            WHEN typeof(record.collection) = 'text' AND length(CAST(record.collection AS BLOB)) BETWEEN 1 AND 317
              AND typeof(record.rkey) = 'text' AND length(CAST(record.rkey AS BLOB)) BETWEEN 1 AND 512
            THEN record.collection || '/' || record.rkey END AND v.until_generation IS NULL
      WHERE budget.total <= ? AND record.rowid = candidate.record_id
        AND record.space_ref = ? AND record.repo_did = ? AND s.authority_did = ? AND s.space_type = ? AND s.skey = ?
        AND e.owner_incarnation = ? AND EXISTS (SELECT 1 FROM authorized)
    ) SELECT * FROM page
    UNION ALL SELECT NULL, NULL, NULL, NULL, NULL, 0, (${activeEpoch}), 1, session_expires_at,
      (SELECT CASE WHEN total > ? THEN 1 ELSE 0 END FROM budget), (SELECT total FROM budget),
      (SELECT creation_nonce FROM genesis), (SELECT created_at FROM genesis)${valueSentinel} FROM authorized`)
      .bind(...authValues, ...genesisValues, MAX_RECORD_SIZE, MAX_PAGE_COMPARE_BYTES + 1, ref.ref, target.repo, ref.authorityDid,
        ref.spaceType, ref.skey, principal.grant.accountIncarnation, ...filters, target.limit,
        MAX_RECORD_SIZE, maxPageBytes, ref.ref, target.repo,
        ref.authorityDid, ref.spaceType, ref.skey, principal.grant.accountIncarnation, ...epochValues, maxPageBytes);
    return db.batch([
      db.prepare(`UPDATE oauth_replay_clock SET seconds = MAX(seconds, unixepoch(), ?), nonce = ?
        WHERE id = 1 AND typeof(seconds) = 'integer' AND seconds BETWEEN 0 AND 9007199254740991`).bind(now, nonce),
      db.prepare(ASSERT_CLOCK).bind(nonce),
      page,
      db.prepare(REFRESH_CLOCK).bind(nonce),
      db.prepare(ASSERT_CLOCK).bind(nonce),
      db.prepare(`${authorization}, ${genesis}
        SELECT clock.seconds, (SELECT session_expires_at FROM authorized) AS session_expires_at,
          (${activeEpoch}) AS epoch_id, (SELECT creation_nonce FROM genesis) AS genesis_nonce,
          (SELECT created_at FROM genesis) AS genesis_created_at FROM clock`).bind(...authValues, ...genesisValues, ...epochValues),
    ]);
  })().catch(() => null);
  if (!Array.isArray(result) || result.length !== 6 || result.some((entry: { success?: unknown } | null) => entry?.success !== true) ||
    !clockAssertionPassed(result[1]?.results) || !clockAssertionPassed(result[4]?.results) || !windowIsLive(principal)) {
    return { tag: 'unauthorized' };
  }
  const finalRows = result[5]?.results;
  if (!Array.isArray(finalRows) || finalRows.length !== 1) return { tag: 'unauthorized' };
  const final = finalRows[0];
  if (!final || typeof final !== 'object' || Array.isArray(final)) return { tag: 'unauthorized' };
  const clock = final.seconds;
  const expiry = final.session_expires_at;
  const epoch = final.epoch_id;
  if (typeof clock !== 'number' || !Number.isSafeInteger(clock) || clock < now ||
    principal.expiresAt <= clock || clock - principal.proofIssuedAt > DPOP_PROOF_MAX_AGE_SEC ||
    principal.proofIssuedAt - clock > DPOP_PROOF_FUTURE_SKEW_SEC ||
    typeof expiry !== 'number' || !Number.isSafeInteger(expiry) || expiry <= clock) {
    return { tag: 'unauthorized' };
  }
  const selected = result[2]?.results;
  if (!Array.isArray(selected) || selected.length > target.limit + 1 ||
    selected.some((row) => !row || typeof row !== 'object' || Array.isArray(row))) {
    return { tag: 'unauthorized' };
  }
  const rows = selected as ListRow[];
  const sentinels = rows.filter((row) => row.sentinel === 1);
  const records = rows.filter((row) => row.sentinel === 0);
  if (sentinels.length !== 1 || records.length > target.limit || sentinels.length + records.length !== rows.length ||
    sentinels[0].session_expires_at !== expiry || records.some((row) => row.session_expires_at !== null)) {
    return { tag: 'unauthorized' };
  }
  if (epoch === null) {
    const sentinel = sentinels[0];
    const createdAt = final.genesis_created_at;
    const after = Math.floor(Date.now() / 1000);
    if (!personal || sentinel.epoch_id !== null || records.length !== 0 || sentinel.too_large !== 0 ||
      sentinel.budget_total !== 0 || !validLifecycleNonce(final.genesis_nonce) ||
      typeof createdAt !== 'number' || !Number.isSafeInteger(createdAt) || createdAt < 0 ||
      sentinel.collection !== null || sentinel.rkey !== null || sentinel.cid !== null ||
      sentinel.repo_rev !== null || sentinel.head_rev !== null || sentinel.consistent !== 0 ||
      (!target.excludeValues && sentinel.value_cbor !== null) ||
      sentinel.genesis_nonce !== final.genesis_nonce || sentinel.genesis_created_at !== createdAt ||
      request.signal.aborted || env.ALTERAN_DB !== db || !windowIsLiveAt(principal, after) || expiry <= after) {
      return { tag: 'unauthorized' };
    }
    return { tag: 'found', records: [], complete: genesisListCompletion(handle, {
      nonce: final.genesis_nonce, createdAt,
    }) };
  }
  if (typeof epoch !== 'string' || !epoch || new TextEncoder().encode(epoch).byteLength > 128 ||
    final.genesis_nonce !== null || final.genesis_created_at !== null ||
    sentinels[0].genesis_nonce !== null || sentinels[0].genesis_created_at !== null ||
    records.some((row) => row.genesis_nonce !== null || row.genesis_created_at !== null)) return { tag: 'unauthorized' };
  const failure = (tag: 'invalid' | 'tooLarge'): AuthorizedSpaceListResult => {
    const after = Math.floor(Date.now() / 1000);
    if (request.signal.aborted || !windowIsLiveAt(principal, after) || expiry <= after) return { tag: 'unauthorized' };
    return { tag, complete: completion(handle, epoch) };
  };
  if (sentinels[0].epoch_id !== epoch || records.some((row) => row.epoch_id !== epoch)) return { tag: 'unauthorized' };
  if (sentinels[0].too_large !== 0 && sentinels[0].too_large !== 1) return failure('invalid');
  if (sentinels[0].too_large === 1) return records.length === 0 ? failure('tooLarge') : failure('invalid');
  if (records.some((row) => row.too_large !== 0)) return failure('invalid');
  let previous = target.cursorPath;
  let cursor: string | undefined;
  let entries: ListedSpaceRecord[];
  try {
    records.sort((left, right) => {
      const a = rowPath(left), b = rowPath(right);
      return a < b ? 1 : a > b ? -1 : 0;
    });
    entries = records.map((row): ListedSpaceRecord => {
      if (!isValidNsid(row.collection) || !isValidRecordKey(row.rkey) || typeof row.cid !== 'string' ||
        parseCanonicalRepoCid(row.cid)?.toString() !== row.cid || !isValidTid(row.repo_rev) || !isValidTid(row.head_rev) ||
        row.repo_rev > row.head_rev || row.consistent !== 1 ||
        (target.collection !== null && row.collection !== target.collection)) throw invalidState();
      const path = `${row.collection}/${row.rkey}`;
      if (previous !== null && previous <= path) throw invalidState();
      previous = path;
      cursor = captureRecordIdentity({ space: ref.ref, repo: target.repo, collection: row.collection, rkey: row.rkey }).uri;
      return { collection: row.collection, rkey: row.rkey, cid: row.cid };
    });
  } catch { return failure('invalid'); }
  if (!target.excludeValues) {
    try {
      let totalBytes = 0;
      let totalItems = 0;
      for (const row of records) {
        const bytes = row.value_cbor;
        if (!Array.isArray(bytes) || bytes.length < 1 || bytes.length > MAX_RECORD_SIZE) return failure('invalid');
        totalBytes += bytes.length;
        if (totalBytes > MAX_PAGE_VALUE_BYTES) return failure('tooLarge');
        for (let index = 0; index < bytes.length; index++) {
          const byte = bytes[index];
          if (!Object.hasOwn(bytes, index) || typeof byte !== 'number' || !Number.isInteger(byte) || byte < 0 || byte > 255) {
            return failure('invalid');
          }
        }
        const inspected = inspectRecordCborBounds(Uint8Array.from(bytes), MAX_RECORD_CBOR_ITEMS - totalItems);
        if (inspected.tag !== 'valid') return failure(inspected.tag === 'unsupported' ? 'tooLarge' : 'invalid');
        totalItems += inspected.items;
        if (totalItems > MAX_RECORD_CBOR_ITEMS) return failure('tooLarge');
      }
      entries = records.map((row, index) => ({
        ...entries[index],
        record: decodeSpaceRecord(row as SpaceRecordRow, entries[index].collection),
      }));
    } catch { return failure('invalid'); }
  }
  const after = Math.floor(Date.now() / 1000);
  if (request.signal.aborted || !windowIsLiveAt(principal, after) || expiry <= after) return { tag: 'unauthorized' };
  const complete = completion(handle, epoch);
  return { tag: 'found', records: entries, ...(entries.length === target.limit ? { cursor } : {}), complete };
}

function clockAssertionPassed(rows: unknown): boolean {
  return Array.isArray(rows) && rows.length === 1 && rows[0]?.valid === 1;
}
function invalidState(): SpaceStorageError {
  return new SpaceStorageError('InvalidRepoState', 'Invalid Space record metadata');
}
function rowPath(row: ListRow): string {
  if (!isValidNsid(row.collection) || !isValidRecordKey(row.rkey)) throw invalidState();
  return `${row.collection}/${row.rkey}`;
}
