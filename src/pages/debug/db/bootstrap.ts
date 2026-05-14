import type { APIContext } from 'astro';
import { debugNotFound, isDebugRouteAllowed } from '../../../lib/debug-routes';

export const prerender = false;

export async function POST({ locals, request }: APIContext) {
  const { env } = locals.runtime;
  if (!isDebugRouteAllowed(env, request)) return debugNotFound();

  const db = env.ALTERAN_DB;
  await db.exec("CREATE TABLE IF NOT EXISTS record (uri TEXT PRIMARY KEY, cid TEXT NOT NULL, json TEXT NOT NULL, created_at INTEGER DEFAULT (strftime('%s','now')));");
  await db.exec("CREATE TABLE IF NOT EXISTS blob (cid TEXT PRIMARY KEY, key TEXT NOT NULL, mime TEXT NOT NULL, size INTEGER NOT NULL);");
  await db.exec("CREATE TABLE IF NOT EXISTS blob_usage (record_uri TEXT NOT NULL, key TEXT NOT NULL);");
  await db.exec("CREATE TABLE IF NOT EXISTS repo_root (did TEXT PRIMARY KEY, commit_cid TEXT NOT NULL, rev INTEGER NOT NULL);");
  // Indexes
  await db.exec("CREATE INDEX IF NOT EXISTS record_cid_idx ON record(cid);");
  await db.exec("CREATE INDEX IF NOT EXISTS blob_usage_record_idx ON blob_usage(record_uri);");
  return new Response('ok');
}
