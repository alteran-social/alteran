import type { APIContext } from 'astro';
import { putRecord as dalPutRecord, getRecord as dalGetRecord } from '../db/dal';

export async function POST_db_bootstrap(ctx: APIContext) {
  const env: any = (ctx.locals as any).runtime?.env ?? (ctx.locals as any) ?? (globalThis as any);
  const db = env.ALTERAN_DB;
  await db.exec("CREATE TABLE IF NOT EXISTS record (uri TEXT PRIMARY KEY, cid TEXT NOT NULL, json TEXT NOT NULL, created_at INTEGER DEFAULT (strftime('%s','now')));");
  await db.exec("CREATE TABLE IF NOT EXISTS blob (cid TEXT PRIMARY KEY, key TEXT NOT NULL, mime TEXT NOT NULL, size INTEGER NOT NULL);");
  await db.exec("CREATE TABLE IF NOT EXISTS blob_usage (record_uri TEXT NOT NULL, key TEXT NOT NULL);");
  await db.exec("CREATE TABLE IF NOT EXISTS repo_root (did TEXT PRIMARY KEY, commit_cid TEXT NOT NULL, rev INTEGER NOT NULL);");
  await db.exec("CREATE INDEX IF NOT EXISTS record_cid_idx ON record(cid);");
  await db.exec("CREATE INDEX IF NOT EXISTS blob_usage_record_idx ON blob_usage(record_uri);");
  return new Response('ok');
}

export async function POST_record(ctx: APIContext) {
  const env: any = (ctx.locals as any).runtime?.env ?? (ctx.locals as any) ?? (globalThis as any);
  const body: any = await ctx.request.json().catch(() => ({} as any));
  const uri = body.uri;
  if (!uri) return new Response('missing uri', { status: 400 });
  const row = { uri, cid: 'cid-dev', json: JSON.stringify(body.json ?? { hello: 'world' }) } as const;
  await dalPutRecord(env, row as any);
  return Response.json({ ok: true });
}

export async function GET_record(ctx: APIContext) {
  const env: any = (ctx.locals as any).runtime?.env ?? (ctx.locals as any) ?? (globalThis as any);
  const url = new URL(ctx.request.url);
  const uri = url.searchParams.get('uri');
  if (!uri) return new Response('missing uri', { status: 400 });
  const row = await dalGetRecord(env, uri);
  if (!row) return new Response('Not Found', { status: 404 });
  return Response.json(row);
}
