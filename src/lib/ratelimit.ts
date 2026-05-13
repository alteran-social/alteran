import type { Env } from '../env';

// Rate limiting (best-effort, D1 based)
export async function checkRate(env: Env, request: Request, bucket: 'writes' | 'blob'): Promise<Response | null> {
  try {
    const limit = Number((env.PDS_RATE_LIMIT_PER_MIN as string | undefined) ?? (bucket === 'blob' ? 30 : 60));
    const now = Date.now();
    const windowMs = 60_000;
    const win = Math.floor(now / windowMs);
    const ip = request.headers.get('cf-connecting-ip') ?? request.headers.get('x-forwarded-for') ?? '127.0.0.1';
    await env.ALTERAN_DB.exec("CREATE TABLE IF NOT EXISTS rate_limit (ip TEXT NOT NULL, bucket TEXT NOT NULL, window INTEGER NOT NULL, count INTEGER NOT NULL, PRIMARY KEY (ip,bucket,window))");
    const row: any = await env.ALTERAN_DB.prepare('SELECT count FROM rate_limit WHERE ip=? AND bucket=? AND window=?').bind(ip, bucket, win).first();
    const count = row?.count ? Number(row.count) : 0;
    if (count >= limit) return rateLimited();
    if (count === 0) {
      await env.ALTERAN_DB.prepare('INSERT OR REPLACE INTO rate_limit (ip,bucket,window,count) VALUES (?,?,?,1)').bind(ip, bucket, win).run();
    } else {
      await env.ALTERAN_DB.prepare('UPDATE rate_limit SET count=count+1 WHERE ip=? AND bucket=? AND window=?').bind(ip, bucket, win).run();
    }

    const headers = new Headers();
    headers.set('x-ratelimit-limit', String(limit));
    headers.set('x-ratelimit-remaining', String(Math.max(0, limit - count - 1)));
    headers.set('x-ratelimit-window', '60s');

    return null;
  } catch {
    return null; // fail-open
  }
}

function rateLimited() {
  return new Response(JSON.stringify({ error: 'RateLimited' }), {
    status: 429,
    headers: { 'Content-Type': 'application/json' },
  });
}
