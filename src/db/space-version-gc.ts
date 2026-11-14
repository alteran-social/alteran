import { isValidNsid, isValidRecordKey } from "@atproto/syntax-spaces";
import type { Env } from "../env";
import { copyPlainRecord } from "../lib/spaces/plain-values";
import { pruneExpiredSpaceSnapshotLeases } from "./space-lease-expiry";
import { assertLocalSpaceRepo, parseSpaceRef } from "./space-ref";
import { SpaceStorageError } from "./space-types";

const MAXIMUM_CANDIDATES = 100;
const MAXIMUM_SAFE_INTEGER = 9007199254740991;

export type SpaceVersionGcCursor = {
  readonly spaceRef: string;
  readonly repoDid: string;
  readonly epochId: string;
  readonly untilGeneration: number;
  readonly path: string;
  readonly fromGeneration: number;
};

export type SpaceVersionGcPage = {
  readonly pruned: number;
  readonly cursor: SpaceVersionGcCursor | null;
};

type Candidate = {
  readonly untilGeneration: number;
  readonly path: string;
  readonly fromGeneration: number;
};
type CandidateRow = {
  readonly until_generation: unknown;
  readonly path: unknown;
  readonly from_generation: unknown;
};

const ACTIVE_EPOCH = `FROM space_repo h
  JOIN space_epoch e ON e.id = h.active_epoch_id AND e.space_ref = h.space_ref
    AND e.repo_did = h.repo_did AND e.state = 'active'
  JOIN space s ON s.space_ref = h.space_ref AND s.deleted_at IS NULL
  WHERE h.space_ref = ? AND h.repo_did = ?`;

const CREATE_ATTEMPT =
  `INSERT INTO space_gc_attempt (id, space_ref, repo_did, epoch_id)
  SELECT ?, h.space_ref, h.repo_did, h.active_epoch_id ${ACTIVE_EPOCH} AND h.active_epoch_id = ?`;

const ASSERT_ATTEMPT = `SELECT CASE WHEN EXISTS (
  SELECT 1 FROM space_gc_attempt g JOIN space_repo h ON h.space_ref = g.space_ref AND h.repo_did = g.repo_did
    AND h.active_epoch_id = g.epoch_id
  JOIN space_epoch e ON e.id = g.epoch_id AND e.space_ref = g.space_ref AND e.repo_did = g.repo_did AND e.state = 'active'
  JOIN space s ON s.space_ref = g.space_ref AND s.deleted_at IS NULL
  WHERE g.id = ? AND g.space_ref = ? AND g.repo_did = ? AND g.epoch_id = ?
) THEN 1 ELSE json('{') END AS valid`;

const SCAN_FIELDS = `
  CASE WHEN typeof(v.until_generation) = 'integer' AND v.until_generation BETWEEN 1 AND ${MAXIMUM_SAFE_INTEGER}
    THEN v.until_generation END AS until_generation,
  CASE WHEN typeof(v.path) = 'text' AND length(CAST(v.path AS BLOB)) BETWEEN 1 AND 830 THEN v.path END AS path,
  CASE WHEN typeof(v.from_generation) = 'integer' AND v.from_generation BETWEEN 1 AND ${MAXIMUM_SAFE_INTEGER}
    THEN v.from_generation END AS from_generation`;
const SCAN_SOURCE =
  `FROM space_record_version v INDEXED BY space_record_version_gc_candidates
  WHERE v.epoch_id = ? AND v.space_ref = ? AND v.repo_did = ? AND v.until_generation IS NOT NULL`;

export const SPACE_VERSION_GC_FIRST_SQL = `SELECT ${SCAN_FIELDS} ${SCAN_SOURCE}
  ORDER BY v.until_generation, v.path COLLATE BINARY, v.from_generation LIMIT ?`;
export const SPACE_VERSION_GC_NEXT_SQL = `WITH same_path AS MATERIALIZED (
  SELECT ${SCAN_FIELDS} ${SCAN_SOURCE}
    AND v.until_generation = ? AND v.path = ? COLLATE BINARY AND v.from_generation > ?
  ORDER BY v.from_generation LIMIT ?
), later_path AS MATERIALIZED (
  SELECT ${SCAN_FIELDS} ${SCAN_SOURCE}
    AND v.until_generation = ? AND v.path > ? COLLATE BINARY
  ORDER BY v.path COLLATE BINARY, v.from_generation LIMIT ?
), later_generation AS MATERIALIZED (
  SELECT ${SCAN_FIELDS} ${SCAN_SOURCE}
    AND v.until_generation > ?
  ORDER BY v.until_generation, v.path COLLATE BINARY, v.from_generation LIMIT ?
)
SELECT * FROM (
  SELECT * FROM same_path UNION ALL SELECT * FROM later_path UNION ALL SELECT * FROM later_generation
) ORDER BY until_generation, path COLLATE BINARY, from_generation LIMIT ?`;

const MATCH_CANDIDATES =
  `FROM json_each(?) item CROSS JOIN space_record_version v INDEXED BY space_record_version_gc_candidates
  WHERE v.epoch_id = ? AND v.space_ref = ? AND v.repo_did = ? AND v.until_generation = json_extract(item.value, '$[0]')
    AND v.path = json_extract(item.value, '$[1]') AND v.from_generation = json_extract(item.value, '$[2]')
    AND v.until_generation IS NOT NULL
    AND EXISTS (SELECT 1 FROM space_gc_attempt g WHERE g.id = ? AND g.epoch_id = v.epoch_id
      AND g.space_ref = v.space_ref AND g.repo_did = v.repo_did)
    AND NOT EXISTS (SELECT 1 FROM space_snapshot_lease l INDEXED BY space_snapshot_lease_epoch_generation
      WHERE l.epoch_id = v.epoch_id AND l.space_ref = v.space_ref AND l.repo_did = v.repo_did
        AND l.generation >= v.from_generation AND l.generation < v.until_generation)`;

export const SPACE_VERSION_GC_DELETE_SQL =
  `DELETE FROM space_record_version NOT INDEXED WHERE rowid IN (
  SELECT v.rowid ${MATCH_CANDIDATES}
)`;

const ASSERT_DELETED =
  `SELECT CASE WHEN NOT EXISTS (SELECT 1 ${MATCH_CANDIDATES})
  THEN 1 ELSE json('{') END AS valid`;
const DELETE_ATTEMPT =
  "DELETE FROM space_gc_attempt WHERE id = ? AND space_ref = ? AND repo_did = ? AND epoch_id = ?";
const ASSERT_ATTEMPT_REMOVED =
  `SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM space_gc_attempt WHERE id = ?)
  THEN 1 ELSE json('{') END AS valid`;

/** Process one bounded keyset page. A null cursor starts a new sweep cycle. */
export async function pruneSpaceRecordVersionsPage(
  env: Env,
  spaceRef: string,
  repoDid: string,
  inputCursor: SpaceVersionGcCursor | null = null,
  batchSize = MAXIMUM_CANDIDATES,
): Promise<SpaceVersionGcPage> {
  parseSpaceRef(spaceRef);
  const cursor = inputCursor === null
    ? null
    : captureCursor(inputCursor, spaceRef, repoDid);
  if (
    !Number.isInteger(batchSize) || batchSize < 1 ||
    batchSize > MAXIMUM_CANDIDATES
  ) throw invalidRequest();
  await assertLocalSpaceRepo(env, repoDid);
  await pruneExpiredSpaceSnapshotLeases(env, spaceRef, repoDid);
  const head = await env.ALTERAN_DB.prepare(
    `SELECT CASE WHEN typeof(h.active_epoch_id) = 'text'
    AND length(CAST(h.active_epoch_id AS BLOB)) BETWEEN 1 AND 128 THEN h.active_epoch_id END AS epoch_id ${ACTIVE_EPOCH}`,
  )
    .bind(spaceRef, repoDid).first<{ epoch_id: unknown }>();
  if (!head) {
    throw new SpaceStorageError("RepoNotFound", "Space repo is unavailable");
  }
  if (typeof head.epoch_id !== "string" || !head.epoch_id) throw invalidState();
  const epochId = head.epoch_id;
  if (cursor && cursor.epochId !== epochId) throw invalidCursor();

  const scanId = crypto.randomUUID();
  const scanIdentity = [scanId, spaceRef, repoDid, epochId] as const;
  const scanLimit = batchSize + 1;
  const scan = cursor
    ? env.ALTERAN_DB.prepare(SPACE_VERSION_GC_NEXT_SQL).bind(
      epochId,
      spaceRef,
      repoDid,
      cursor.untilGeneration,
      cursor.path,
      cursor.fromGeneration,
      scanLimit,
      epochId,
      spaceRef,
      repoDid,
      cursor.untilGeneration,
      cursor.path,
      scanLimit,
      epochId,
      spaceRef,
      repoDid,
      cursor.untilGeneration,
      scanLimit,
      scanLimit,
    )
    : env.ALTERAN_DB.prepare(SPACE_VERSION_GC_FIRST_SQL).bind(
      epochId,
      spaceRef,
      repoDid,
      scanLimit,
    );
  const scanResult = await env.ALTERAN_DB.batch([
    env.ALTERAN_DB.prepare(CREATE_ATTEMPT).bind(...scanIdentity),
    env.ALTERAN_DB.prepare(ASSERT_ATTEMPT).bind(...scanIdentity),
    scan,
    env.ALTERAN_DB.prepare(ASSERT_ATTEMPT).bind(...scanIdentity),
    env.ALTERAN_DB.prepare(DELETE_ATTEMPT).bind(...scanIdentity),
    env.ALTERAN_DB.prepare(ASSERT_ATTEMPT_REMOVED).bind(scanId),
  ]);
  const candidateRows = scanResult[2]?.results as CandidateRow[] | undefined;
  if (!candidateRows || candidateRows.length > batchSize + 1) {
    throw invalidState();
  }
  const candidates = candidateRows.map(decodeCandidate);
  const page = candidates.slice(0, batchSize);
  if (!page.length) return { pruned: 0, cursor: null };
  const last = page[page.length - 1];
  const next = candidates.length > batchSize
    ? Object.freeze({ spaceRef, repoDid, epochId, ...last })
    : null;
  const encoded = JSON.stringify(
    page.map((item) => [item.untilGeneration, item.path, item.fromGeneration]),
  );
  const deleteId = crypto.randomUUID();
  const deleteIdentity = [deleteId, spaceRef, repoDid, epochId] as const;
  const candidateArguments = [
    encoded,
    epochId,
    spaceRef,
    repoDid,
    deleteId,
  ] as const;
  const deletion = await env.ALTERAN_DB.batch([
    env.ALTERAN_DB.prepare(CREATE_ATTEMPT).bind(...deleteIdentity),
    env.ALTERAN_DB.prepare(ASSERT_ATTEMPT).bind(...deleteIdentity),
    env.ALTERAN_DB.prepare(SPACE_VERSION_GC_DELETE_SQL).bind(
      ...candidateArguments,
    ),
    env.ALTERAN_DB.prepare("SELECT changes() AS count"),
    env.ALTERAN_DB.prepare(ASSERT_DELETED).bind(...candidateArguments),
    env.ALTERAN_DB.prepare(ASSERT_ATTEMPT).bind(...deleteIdentity),
    env.ALTERAN_DB.prepare(DELETE_ATTEMPT).bind(...deleteIdentity),
    env.ALTERAN_DB.prepare(ASSERT_ATTEMPT_REMOVED).bind(deleteId),
  ]);
  const count = (deletion[3]?.results?.[0] as { count?: unknown } | undefined)
    ?.count;
  if (
    typeof count !== "number" || !Number.isSafeInteger(count) || count < 0 ||
    count > page.length
  ) throw invalidState();
  return { pruned: count, cursor: next };
}

function decodeCandidate(row: CandidateRow): Candidate {
  if (
    typeof row.until_generation !== "number" ||
    !Number.isSafeInteger(row.until_generation) ||
    typeof row.from_generation !== "number" ||
    !Number.isSafeInteger(row.from_generation) ||
    row.from_generation < 1 || row.until_generation <= row.from_generation ||
    typeof row.path !== "string" || !validPath(row.path)
  ) throw invalidState();
  return {
    untilGeneration: row.until_generation,
    path: row.path,
    fromGeneration: row.from_generation,
  };
}

function captureCursor(
  value: SpaceVersionGcCursor,
  spaceRef: string,
  repoDid: string,
): SpaceVersionGcCursor {
  const fields = copyPlainRecord(value, [
    "spaceRef",
    "repoDid",
    "epochId",
    "untilGeneration",
    "path",
    "fromGeneration",
  ]);
  if (
    !fields || fields.spaceRef !== spaceRef || fields.repoDid !== repoDid ||
    typeof fields.epochId !== "string" || !fields.epochId ||
    fields.epochId.length > 128 ||
    typeof fields.untilGeneration !== "number" ||
    !Number.isSafeInteger(fields.untilGeneration) ||
    typeof fields.fromGeneration !== "number" ||
    !Number.isSafeInteger(fields.fromGeneration) ||
    fields.fromGeneration < 1 ||
    fields.untilGeneration <= fields.fromGeneration ||
    typeof fields.path !== "string" || !validPath(fields.path)
  ) throw invalidCursor();
  return {
    spaceRef,
    repoDid,
    epochId: fields.epochId,
    untilGeneration: fields.untilGeneration,
    path: fields.path,
    fromGeneration: fields.fromGeneration,
  };
}

function validPath(value: string): boolean {
  if (value.length > 830) return false;
  const parts = value.split("/");
  return parts.length === 2 && isValidNsid(parts[0]) &&
    isValidRecordKey(parts[1]);
}

function invalidRequest(): SpaceStorageError {
  return new SpaceStorageError(
    "InvalidRequest",
    "Invalid Space version cleanup request",
  );
}
function invalidCursor(): SpaceStorageError {
  return new SpaceStorageError(
    "InvalidCursor",
    "Invalid Space version cleanup cursor",
  );
}
function invalidState(): SpaceStorageError {
  return new SpaceStorageError(
    "InvalidRepoState",
    "Invalid Space version cleanup state",
  );
}
