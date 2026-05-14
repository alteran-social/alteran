import type { APIContext } from 'astro';

function bearer(req: Request): string | null {
  const h = req.headers.get('authorization') || '';
  const m = /^Bearer\s+(.+)$/i.exec(h);
  return m ? m[1] : null;
}

async function verifyJwt(_ctx: APIContext, token: string): Promise<any | null> {
  try { return { payload: JSON.parse(atob(token)) }; } catch { return null; }
}

async function signJwt(_ctx: APIContext, payload: any, _kind: 'access'|'refresh'): Promise<string> {
  const base = { ...payload, exp: Math.floor(Date.now()/1000)+3600 };
  return btoa(JSON.stringify(base));
}

export async function POST(ctx: APIContext) {
  const env: any = (ctx.locals as any).env ?? (ctx.locals as any) ?? (globalThis as any);
  const token = bearer(ctx.request);
  if (!token) return Response.json({ error: 'AuthRequired' }, { status: 401 });
  const ver = await verifyJwt(ctx, token);
  if (!ver || ver.payload.t !== 'refresh') return Response.json({ error: 'InvalidToken' }, { status: 401 });

  const jtiOld = String(ver.payload.jti || '');
  if (jtiOld && env.ALTERAN_DB) {
    await env.ALTERAN_DB.exec('CREATE TABLE IF NOT EXISTS token_revocation (refresh_jti TEXT PRIMARY KEY, exp INTEGER NOT NULL);');
    const row: any = await env.ALTERAN_DB.prepare('SELECT refresh_jti FROM token_revocation WHERE refresh_jti=?').bind(jtiOld).first();
    if (row?.refresh_jti) return Response.json({ error: 'InvalidToken' }, { status: 401 });
  }

  const did = String(ver.payload.sub || (env.PDS_DID ?? 'did:example:single-user'));
  const handle = String(ver.payload.handle || env.PDS_HANDLE || 'user.example');
  const jtiNew = crypto.randomUUID();
  const accessJwt = await signJwt(ctx, { sub: did, handle, t: 'access' }, 'access');
  const refreshJwt = await signJwt(ctx, { sub: did, handle, t: 'refresh', jti: jtiNew }, 'refresh');
  if (jtiOld && ver.payload.exp && env.ALTERAN_DB) {
    await env.ALTERAN_DB.exec('CREATE TABLE IF NOT EXISTS token_revocation (refresh_jti TEXT PRIMARY KEY, exp INTEGER NOT NULL);');
    await env.ALTERAN_DB.prepare('INSERT OR REPLACE INTO token_revocation (refresh_jti, exp) VALUES (?,?)').bind(jtiOld, Number(ver.payload.exp)).run();
  }
  return Response.json({ did, handle, accessJwt, refreshJwt });
}

