import type { APIContext } from 'astro';

export const prerender = false;

export async function POST({ locals }: APIContext) {
  const { env } = locals.runtime;
  // Gate to development by default. In production, require local hostname explicitly.
  const envName = (env as any).ENVIRONMENT as string | undefined;
  const host = env.PDS_HOSTNAME as string | undefined;
  const isLocal = envName !== 'production' && (!host || host.includes('localhost') || host.startsWith('127.') || host === '::1');
  if (!isLocal) {
    return new Response('Not Found', { status: 404 });
  }
  const db = env.ALTERAN_DB;
  await db.exec("CREATE TABLE IF NOT EXISTS record (uri TEXT PRIMARY KEY, cid TEXT NOT NULL, json TEXT NOT NULL, created_at INTEGER DEFAULT (strftime('%s','now')));");
  await db.exec("CREATE TABLE IF NOT EXISTS blob (cid TEXT NOT NULL, did TEXT NOT NULL, key TEXT NOT NULL, mime TEXT NOT NULL, size INTEGER NOT NULL, uploaded_at INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (did, cid));");
  await db.exec("CREATE TABLE IF NOT EXISTS blob_usage (did TEXT NOT NULL, record_uri TEXT NOT NULL, key TEXT NOT NULL, PRIMARY KEY (did, record_uri, key));");
  await db.exec("CREATE TABLE IF NOT EXISTS repo_root (did TEXT PRIMARY KEY, commit_cid TEXT NOT NULL, rev INTEGER NOT NULL);");
  // Indexes
  await db.exec("CREATE INDEX IF NOT EXISTS record_cid_idx ON record(cid);");
  await db.exec("CREATE INDEX IF NOT EXISTS blob_usage_record_idx ON blob_usage(did, record_uri);");
  await db.exec("CREATE INDEX IF NOT EXISTS blob_usage_did_key_idx ON blob_usage(did, key);");
  return new Response('ok');
}
