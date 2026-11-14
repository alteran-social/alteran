import {
  isValidNsid,
  isValidRecordKey,
  isValidTid,
} from "@atproto/syntax-spaces";
import type { Env } from "../env";
import { spaceSetHashDigest } from "../lib/spaces/lthash";
import { copyPlainRecordWithExtensions } from "../lib/spaces/plain-values";
import { parseCanonicalRepoCid } from "../lib/spaces/repo-cid";
import { assertLocalSpaceRepo, parseSpaceRef } from "./space-ref";
import { validSpaceRecordBlock } from "./space-record-block";
import { SpaceStorageError } from "./space-types";

const MAX_PAGE_OPERATIONS = 1000;
const MAX_PAGE_VALUE_BYTES = 1024 * 1024;

export type SpaceRepoOperation = {
  readonly rev: string;
  readonly collection: string;
  readonly rkey: string;
  readonly cid: string | null;
  readonly prev: string | null;
  readonly value?: Uint8Array;
};

export type SpaceRepoOpsPage =
  | { readonly tag: "fullSync" }
  | {
    readonly tag: "page";
    readonly commit: {
      readonly space: string;
      readonly repo: string;
      readonly rev: string;
      readonly data: Uint8Array;
    };
    readonly operations: readonly SpaceRepoOperation[];
    readonly cursor: string | null;
  };

type OperationRow = {
  rev: string | null;
  ordinal: number | null;
  collection: string | null;
  rkey: string | null;
  cid: string | null;
  prev: string | null;
  value_cbor: number[] | null;
  has_value: number;
  consistent: number;
  metadata_valid: number;
  sentinel: number;
  candidate_count: number;
};

/**
 * Read a page and its head from one D1 snapshot. The caller must authorize the
 * repo and authenticate the commit; the last page's digest detects divergence.
 * Log pruning, imports and epoch replacement require an epoch history fence.
 */
export async function readSpaceRepoOps(
  env: Env,
  space: string,
  repo: string,
  input: {
    readonly since: string;
    readonly cursor?: string;
    readonly limit?: number;
    readonly excludeValues?: boolean;
  },
): Promise<SpaceRepoOpsPage> {
  parseSpaceRef(space);
  const options = copyPlainRecordWithExtensions(input, 4);
  if (
    !options ||
    Object.keys(options).some((key) =>
      !["since", "cursor", "limit", "excludeValues"].includes(key)
    )
  ) {
    throw invalidRequest();
  }
  const since = options.since;
  const limit = options.limit ?? 100;
  const excludeValues = options.excludeValues ?? false;
  if (
    typeof since !== "string" || !isValidTid(since) ||
    !Number.isInteger(limit) ||
    typeof limit !== "number" || limit < 1 || limit > MAX_PAGE_OPERATIONS ||
    typeof excludeValues !== "boolean"
  ) {
    throw invalidRequest();
  }
  const cursor = options.cursor === undefined
    ? null
    : parseCursor(options.cursor);
  await assertLocalSpaceRepo(env, repo);
  const [headResult, pageResult] = await env.ALTERAN_DB.batch([
    env.ALTERAN_DB.prepare(`
      SELECT CASE WHEN typeof(h.rev) = 'text' AND length(CAST(h.rev AS BLOB)) = 13 THEN h.rev END AS rev,
        CASE WHEN typeof(h.set_hash) = 'blob' AND length(h.set_hash) = 2048 THEN h.set_hash END AS set_hash,
        CASE WHEN typeof(h.generation) = 'integer' AND h.generation BETWEEN 1 AND 9007199254740991
          THEN h.generation END AS generation,
        (?3 = h.rev OR EXISTS (
          SELECT 1 FROM space_op o WHERE o.space_ref = h.space_ref AND o.repo_did = h.repo_did AND o.rev = ?3
        )) AS known_since
      FROM space_repo h
      JOIN space_epoch e ON e.id = h.active_epoch_id AND e.space_ref = h.space_ref
        AND e.repo_did = h.repo_did AND e.state = 'active'
      JOIN space s ON s.space_ref = h.space_ref AND s.deleted_at IS NULL
      WHERE h.space_ref = ?1 AND h.repo_did = ?2
    `).bind(space, repo, since),
    env.ALTERAN_DB.prepare(`
      WITH repo AS (
        SELECT h.space_ref, h.repo_did, h.active_epoch_id, h.generation
        FROM space_repo h
        JOIN space_epoch e ON e.id = h.active_epoch_id AND e.space_ref = h.space_ref
          AND e.repo_did = h.repo_did AND e.state = 'active'
        JOIN space s ON s.space_ref = h.space_ref AND s.deleted_at IS NULL
        WHERE h.space_ref = ?1 AND h.repo_did = ?2 AND (
          h.rev = ?3 OR EXISTS (SELECT 1 FROM space_op o
            WHERE o.space_ref = h.space_ref AND o.repo_did = h.repo_did AND o.rev = ?3)
        )
      ), candidates AS (
        SELECT o.rev, o.ordinal, o.collection, o.rkey, o.cid, o.prev,
          CASE WHEN ?7 = 1 AND typeof(r.value_cbor) = 'blob' THEN length(r.value_cbor) ELSE 0 END AS value_size
        FROM space_op o JOIN repo h ON h.space_ref = o.space_ref AND h.repo_did = o.repo_did
        LEFT JOIN space_record r ON ?7 = 1 AND r.space_ref = o.space_ref AND r.repo_did = o.repo_did
          AND r.collection = o.collection AND r.rkey = o.rkey AND r.cid = o.cid
        WHERE o.rev > ?3 COLLATE BINARY AND (?4 IS NULL OR o.rev > ?4 COLLATE BINARY
          OR (o.rev = ?4 AND o.ordinal > ?5))
        ORDER BY o.rev COLLATE BINARY, o.ordinal LIMIT ?6
      ), ranked AS (
        SELECT *, ROW_NUMBER() OVER (ORDER BY rev COLLATE BINARY, ordinal) AS position,
          SUM(value_size) OVER (ORDER BY rev COLLATE BINARY, ordinal) AS total_size
        FROM candidates
      )
      SELECT CASE WHEN typeof(p.rev) = 'text' AND length(CAST(p.rev AS BLOB)) = 13 THEN p.rev END AS rev,
        CASE WHEN typeof(p.ordinal) = 'integer' AND p.ordinal BETWEEN 0 AND 9007199254740991 THEN p.ordinal END AS ordinal,
        CASE WHEN typeof(p.collection) = 'text' AND length(CAST(p.collection AS BLOB)) <= 317 THEN p.collection END AS collection,
        CASE WHEN typeof(p.rkey) = 'text' AND length(CAST(p.rkey AS BLOB)) <= 512 THEN p.rkey END AS rkey,
        CASE WHEN p.cid IS NULL OR (typeof(p.cid) = 'text' AND length(CAST(p.cid AS BLOB)) <= 128) THEN p.cid END AS cid,
        CASE WHEN p.prev IS NULL OR (typeof(p.prev) = 'text' AND length(CAST(p.prev AS BLOB)) <= 128) THEN p.prev END AS prev,
        CASE WHEN typeof(r.value_cbor) = 'blob' AND length(r.value_cbor) <= ?9 THEN r.value_cbor END AS value_cbor,
        CASE WHEN r.cid IS NULL THEN 0 ELSE 1 END AS has_value,
        CASE WHEN r.cid IS NULL THEN 1 WHEN typeof(r.value_cbor) = 'blob' AND length(r.value_cbor) <= ?9
          AND typeof(v.value_cbor) = 'blob' AND v.cid = r.cid AND v.repo_rev = r.repo_rev
          AND v.value_cbor IS r.value_cbor AND v.value_size = length(r.value_cbor)
          AND v.from_generation <= h.generation THEN 1 ELSE 0 END AS consistent,
        CASE WHEN typeof(p.rev) = 'text' AND length(CAST(p.rev AS BLOB)) = 13
          AND typeof(p.ordinal) = 'integer' AND p.ordinal BETWEEN 0 AND 9007199254740991
          AND typeof(p.collection) = 'text' AND length(CAST(p.collection AS BLOB)) <= 317
          AND typeof(p.rkey) = 'text' AND length(CAST(p.rkey AS BLOB)) <= 512
          AND (p.cid IS NULL OR (typeof(p.cid) = 'text' AND length(CAST(p.cid AS BLOB)) <= 128))
          AND (p.prev IS NULL OR (typeof(p.prev) = 'text' AND length(CAST(p.prev AS BLOB)) <= 128))
          THEN 1 ELSE 0 END AS metadata_valid,
        0 AS sentinel,
        (SELECT COUNT(*) FROM candidates) AS candidate_count
      FROM ranked p JOIN repo h
      LEFT JOIN space_record r ON ?7 = 1 AND r.space_ref = h.space_ref AND r.repo_did = h.repo_did
        AND r.collection = p.collection AND r.rkey = p.rkey AND r.cid = p.cid
      LEFT JOIN space_record_version v ON v.epoch_id = h.active_epoch_id AND v.space_ref = h.space_ref
        AND v.repo_did = h.repo_did AND v.path = p.collection || '/' || p.rkey AND v.until_generation IS NULL
      WHERE p.position <= ?8 AND p.total_size <= ?9
      UNION ALL SELECT NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, 1, 1, 1, (SELECT COUNT(*) FROM candidates)
      ORDER BY 1 COLLATE BINARY, 2
    `).bind(
      space,
      repo,
      since,
      cursor?.rev ?? null,
      cursor?.ordinal ?? 0,
      limit + 1,
      excludeValues ? 0 : 1,
      limit,
      MAX_PAGE_VALUE_BYTES,
    ),
  ]);

  const head = headResult.results?.[0] as {
    rev: string | null;
    set_hash: number[];
    generation: number;
    known_since: number;
  } | undefined;
  if (!head) {
    throw new SpaceStorageError("RepoNotFound", "Space repo is unavailable");
  }
  if (
    !head.rev || !isValidTid(head.rev) ||
    !Number.isSafeInteger(head.generation) || head.generation < 1 ||
    !validBytes(head.set_hash, 2048) ||
    (head.known_since !== 0 && head.known_since !== 1)
  ) throw invalidState();
  if (!head.known_since) return { tag: "fullSync" };

  const rows = pageResult.results as OperationRow[] | undefined;
  if (
    !rows?.length || rows.filter((row) => row.sentinel === 1).length !== 1
  ) throw invalidState();
  const sentinel = rows.find((row) => row.sentinel === 1);
  if (!sentinel || !Number.isInteger(sentinel.candidate_count)) {
    throw invalidState();
  }
  const candidateCount = sentinel.candidate_count;
  const entries = rows.filter((row) => row.sentinel === 0);
  if (entries.length + 1 !== rows.length) throw invalidState();
  if (
    candidateCount < entries.length || candidateCount > limit + 1 ||
    (candidateCount > 0 && entries.length === 0)
  ) {
    throw invalidState();
  }
  const headRev = head.rev;
  const operations = entries.map((row) => decodeOperation(row, headRev));
  const last = entries.at(-1);
  return {
    tag: "page",
    commit: {
      space,
      repo,
      rev: head.rev,
      data: spaceSetHashDigest(Uint8Array.from(head.set_hash)),
    },
    operations,
    cursor: candidateCount > entries.length && last
      ? `${last.rev}/${last.ordinal}`
      : null,
  };
}

function decodeOperation(
  row: OperationRow,
  headRev: string,
): SpaceRepoOperation {
  if (
    !row.rev || !isValidTid(row.rev) || row.rev > headRev ||
    !Number.isSafeInteger(row.ordinal) ||
    row.ordinal === null || row.ordinal < 0 || !row.collection ||
    !isValidNsid(row.collection) ||
    !row.rkey || !isValidRecordKey(row.rkey) || !validCid(row.cid) ||
    !validCid(row.prev) ||
    (row.cid === null && row.prev === null) ||
    (row.has_value !== 0 && row.has_value !== 1) || row.consistent !== 1 ||
    row.metadata_valid !== 1
  ) {
    throw invalidState();
  }
  const operation: SpaceRepoOperation = {
    rev: row.rev,
    collection: row.collection,
    rkey: row.rkey,
    cid: row.cid,
    prev: row.prev,
  };
  if (!row.has_value) return operation;
  if (!row.cid || !validBytes(row.value_cbor, undefined)) throw invalidState();
  const value = Uint8Array.from(row.value_cbor);
  if (!validSpaceRecordBlock(row.collection, row.cid, value)) throw invalidState();
  return { ...operation, value };
}

function parseCursor(
  value: unknown,
): { readonly rev: string; readonly ordinal: number } {
  if (typeof value !== "string" || value.length > 32) throw invalidCursor();
  const parts = value.split("/");
  if (
    parts.length !== 2 || !isValidTid(parts[0]) ||
    !/^(0|[1-9][0-9]*)$/.test(parts[1])
  ) throw invalidCursor();
  const ordinal = Number(parts[1]);
  if (!Number.isSafeInteger(ordinal)) throw invalidCursor();
  return { rev: parts[0], ordinal };
}

function validCid(value: string | null): boolean {
  if (value === null) return true;
  const cid = parseCanonicalRepoCid(value);
  return cid !== null && cid.toString() === value;
}

function validBytes(
  value: unknown,
  exactLength: number | undefined,
): value is number[] {
  return Array.isArray(value) &&
    (exactLength === undefined || value.length === exactLength) &&
    value.length <= MAX_PAGE_VALUE_BYTES &&
    value.every((byte) => Number.isInteger(byte) && byte >= 0 && byte <= 255);
}

function invalidRequest(): SpaceStorageError {
  return new SpaceStorageError(
    "InvalidRequest",
    "Invalid incremental sync request",
  );
}

function invalidCursor(): SpaceStorageError {
  return new SpaceStorageError(
    "InvalidCursor",
    "Invalid incremental sync cursor",
  );
}

function invalidState(): SpaceStorageError {
  return new SpaceStorageError(
    "InvalidRepoState",
    "Invalid incremental sync state",
  );
}
