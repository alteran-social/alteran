import type { APIContext } from 'astro';
import { RepoManager } from '../services/repo-manager';

async function readJson(req: Request): Promise<any> { try { return await req.json(); } catch { return {}; } }

function bearer(req: Request): string | null { const h = req.headers.get('authorization')||''; const m = /^Bearer\s+(.+)$/i.exec(h); return m?m[1]:null; }
async function verifyJwt(_ctx: APIContext, token: string): Promise<any | null> { try { return { payload: JSON.parse(atob(token)) }; } catch { return null; } }

async function ensureAuth(ctx: APIContext): Promise<boolean> {
  const token = bearer(ctx.request);
  if (!token) return false;
  const ver = await verifyJwt(ctx, token);
  return !!ver;
}

export async function createRecord(ctx: APIContext) {
  if (!(await ensureAuth(ctx))) return Response.json({ error: 'AuthRequired' }, { status: 401 });
  const { collection, rkey, record } = await readJson(ctx.request);
  if (!collection || !record) return Response.json({ error: 'BadRequest' }, { status: 400 });
  const env: any = (ctx.locals as any).env ?? (ctx.locals as any) ?? (globalThis as any);
  const repo = new RepoManager(env);
  const commit = await repo.createRecord(collection, record, rkey);
  return Response.json(commit);
}

export async function putRecord(ctx: APIContext) {
  if (!(await ensureAuth(ctx))) return Response.json({ error: 'AuthRequired' }, { status: 401 });
  const { collection, rkey, record } = await readJson(ctx.request);
  if (!collection || !rkey || !record) return Response.json({ error: 'BadRequest' }, { status: 400 });
  const env: any = (ctx.locals as any).env ?? (ctx.locals as any) ?? (globalThis as any);
  const repo = new RepoManager(env);
  const commit = await repo.putRecord(collection, rkey, record);
  return Response.json(commit);
}

export async function deleteRecord(ctx: APIContext) {
  if (!(await ensureAuth(ctx))) return Response.json({ error: 'AuthRequired' }, { status: 401 });
  const { collection, rkey } = await readJson(ctx.request);
  if (!collection || !rkey) return Response.json({ error: 'BadRequest' }, { status: 400 });
  const env: any = (ctx.locals as any).env ?? (ctx.locals as any) ?? (globalThis as any);
  const repo = new RepoManager(env);
  const commit = await repo.deleteRecord(collection, rkey);
  return Response.json(commit);
}

export async function getRecord(ctx: APIContext) {
  const url = new URL(ctx.request.url);
  const repo = url.searchParams.get('repo') || '';
  const collection = url.searchParams.get('collection') || '';
  const rkey = url.searchParams.get('rkey') || '';
  if (!repo || !collection || !rkey) return Response.json({ error: 'BadRequest' }, { status: 400 });
  const env: any = (ctx.locals as any).env ?? (ctx.locals as any) ?? (globalThis as any);
  const manager = new RepoManager(env);
  const res = await manager.getRecord(collection, rkey);
  if (!res) return Response.json({ error: 'NotFound' }, { status: 404 });
  return Response.json(res);
}
