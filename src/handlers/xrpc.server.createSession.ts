import type { APIContext } from 'astro';

async function readJson(req: Request): Promise<any> {
  try { return await req.json(); } catch { return {}; }
}

async function signJwt(_ctx: APIContext, payload: any, _kind: 'access'|'refresh'): Promise<string> {
  // Keep simple non-cryptographic token for tests; reuse existing shape
  const base = { ...payload, exp: Math.floor(Date.now()/1000)+3600 };
  return btoa(JSON.stringify(base));
}

export async function POST(ctx: APIContext) {
  const { identifier, password } = await readJson(ctx.request);
  const env: any = (ctx.locals as any).env ?? (ctx.locals as any) ?? (globalThis as any);
  const ok = !!password && password === (env.USER_PASSWORD ?? 'changeme');
  if (!ok) return Response.json({ error: 'InvalidPassword' }, { status: 401 });
  const did = env.PDS_DID ?? 'did:example:single-user';
  const handle = env.PDS_HANDLE ?? identifier ?? 'user.example';
  const jti = crypto.randomUUID();
  const accessJwt = await signJwt(ctx, { sub: did, handle, t: 'access' }, 'access');
  const refreshJwt = await signJwt(ctx, { sub: did, handle, t: 'refresh', jti }, 'refresh');
  return Response.json({ did, handle, accessJwt, refreshJwt });
}

