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
  const trigger = await database.prepare(
    "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = 'space_blob_usage_fence_insert'",
  ).first<{ sql: string }>();
  if (!trigger?.sql) throw new Error('Missing blob usage fixture trigger');
  await database.exec('DROP TRIGGER space_blob_usage_fence_insert');
  try {
    await database.prepare(
      `INSERT INTO space_blob_usage (space_ref, repo_did, collection, rkey, cid, key) VALUES (?, ?, ?, ?, ?, ?)`,
    ).bind(spaceRef, repoDid, collection, rkey, cid, key).run();
  } finally {
    await database.exec(trigger.sql.replace(/\n/g, ' '));
  }
}
