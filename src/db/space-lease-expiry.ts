import type { D1PreparedStatement } from "@cloudflare/workers-types";
import type { Env } from "../env";
import { assertLocalSpaceRepo, parseSpaceRef } from "./space-ref";
import { SpaceStorageError } from "./space-types";

const MAXIMUM_BATCH_SIZE = 500;

export const GLOBAL_LEASE_EXPIRY_SQL =
  `DELETE FROM space_snapshot_lease NOT INDEXED WHERE rowid IN (
  SELECT rowid FROM space_snapshot_lease INDEXED BY space_snapshot_lease_expiry
  WHERE expires_at <= unixepoch() ORDER BY expires_at, id LIMIT ?
) AND expires_at <= unixepoch()`;
export const GLOBAL_LEASE_MAXIMUM_EXPIRY_SQL =
  `DELETE FROM space_snapshot_lease NOT INDEXED WHERE rowid IN (
  SELECT rowid FROM space_snapshot_lease INDEXED BY space_snapshot_lease_maximum_expiry
  WHERE maximum_expires_at <= unixepoch() ORDER BY maximum_expires_at, id LIMIT ?
) AND maximum_expires_at <= unixepoch()`;
export const OWNER_LEASE_EXPIRY_SQL =
  `DELETE FROM space_snapshot_lease NOT INDEXED WHERE rowid IN (
  SELECT rowid FROM space_snapshot_lease INDEXED BY space_snapshot_lease_owner_expiry
  WHERE space_ref = ? AND repo_did = ? AND expires_at <= unixepoch() ORDER BY expires_at, id LIMIT ?
) AND space_ref = ? AND repo_did = ? AND expires_at <= unixepoch()`;
export const OWNER_LEASE_MAXIMUM_EXPIRY_SQL =
  `DELETE FROM space_snapshot_lease NOT INDEXED WHERE rowid IN (
  SELECT rowid FROM space_snapshot_lease INDEXED BY space_snapshot_lease_owner_maximum_expiry
  WHERE space_ref = ? AND repo_did = ? AND maximum_expires_at <= unixepoch() ORDER BY maximum_expires_at, id LIMIT ?
) AND space_ref = ? AND repo_did = ? AND maximum_expires_at <= unixepoch()`;

/** Bound each independently indexed expiry branch to the given number of rows. */
export function globalLeaseExpiryStatements(
  env: Env,
  batchSize: number,
): readonly D1PreparedStatement[] {
  assertBatchSize(batchSize);
  return [
    env.ALTERAN_DB.prepare(GLOBAL_LEASE_EXPIRY_SQL).bind(batchSize),
    env.ALTERAN_DB.prepare(GLOBAL_LEASE_MAXIMUM_EXPIRY_SQL).bind(batchSize),
  ];
}

/** Delete up to twice batchSize expired leases for one local Space repo. */
export async function pruneExpiredSpaceSnapshotLeases(
  env: Env,
  spaceRef: string,
  repoDid: string,
  batchSize = 50,
): Promise<number> {
  assertBatchSize(batchSize);
  parseSpaceRef(spaceRef);
  await assertLocalSpaceRepo(env, repoDid);
  const results = await env.ALTERAN_DB.batch([
    env.ALTERAN_DB.prepare(OWNER_LEASE_EXPIRY_SQL).bind(
      spaceRef,
      repoDid,
      batchSize,
      spaceRef,
      repoDid,
    ),
    env.ALTERAN_DB.prepare("SELECT changes() AS count"),
    env.ALTERAN_DB.prepare(OWNER_LEASE_MAXIMUM_EXPIRY_SQL).bind(
      spaceRef,
      repoDid,
      batchSize,
      spaceRef,
      repoDid,
    ),
    env.ALTERAN_DB.prepare("SELECT changes() AS count"),
  ]);
  const first = (results[1]?.results?.[0] as { count?: unknown } | undefined)
    ?.count;
  const second = (results[3]?.results?.[0] as { count?: unknown } | undefined)
    ?.count;
  if (
    typeof first !== "number" || typeof second !== "number" ||
    !Number.isSafeInteger(first) || !Number.isSafeInteger(second) ||
    first < 0 || second < 0 || first > batchSize || second > batchSize
  ) {
    throw new SpaceStorageError(
      "InvalidRepoState",
      "Invalid expired lease cleanup result",
    );
  }
  return first + second;
}

function assertBatchSize(value: number): void {
  if (!Number.isInteger(value) || value < 1 || value > MAXIMUM_BATCH_SIZE) {
    throw new SpaceStorageError(
      "InvalidRequest",
      "Invalid expired lease cleanup limit",
    );
  }
}
