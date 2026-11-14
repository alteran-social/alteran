import type { D1Database } from '@cloudflare/workers-types';

export async function seedLegacySpaceBlobUsage(
  database: D1Database,
  spaceRef: string,
  repoDid: string,
  collection: string,
  rkey: string,
  cid: string,
  key: string,
): Promise<void> {
  await database.batch([
    database.prepare(
      `INSERT INTO space_mutation_attempt (mutation_id, space_ref, repo_did, epoch_id, generation, rev, set_hash)
       SELECT mutation_id, space_ref, repo_did, active_epoch_id, generation, rev, set_hash FROM space_repo
       WHERE space_ref = ? AND repo_did = ?`,
    ).bind(spaceRef, repoDid),
    database.prepare(
      `INSERT INTO space_commit_assertion (mutation_id, valid)
       SELECT mutation_id || ':won', 1 FROM space_repo WHERE space_ref = ? AND repo_did = ?`,
    ).bind(spaceRef, repoDid),
    database.prepare(
      `INSERT INTO space_blob_usage (space_ref, repo_did, collection, rkey, cid, key) VALUES (?, ?, ?, ?, ?, ?)`,
    ).bind(spaceRef, repoDid, collection, rkey, cid, key),
    database.prepare(
      `DELETE FROM space_commit_assertion WHERE mutation_id =
       (SELECT mutation_id || ':won' FROM space_repo WHERE space_ref = ? AND repo_did = ?)`,
    ).bind(spaceRef, repoDid),
    database.prepare(
      `DELETE FROM space_mutation_attempt WHERE mutation_id =
       (SELECT mutation_id FROM space_repo WHERE space_ref = ? AND repo_did = ?)`,
    ).bind(spaceRef, repoDid),
  ]);
}
