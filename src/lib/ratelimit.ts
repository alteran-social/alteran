import type { Env } from '../env';

// Rate limiting (best-effort, D1 based)
export async function checkRate(
  env: Env,
  request: Request,
  bucket: 'writes' | 'blob',
  options: { key?: string; cost?: number } = {},
): Promise<Response | null> {
  try {
    const limit = Number((env.PDS_RATE_LIMIT_PER_MIN as string | undefined) ?? (bucket === 'blob' ? 30 : 60));
    const cost = Math.max(1, Math.floor(options.cost ?? 1));
    const now = Date.now();
    const windowMs = 60_000;
    const win = Math.floor(now / windowMs);
    const key = options.key
      ?? request.headers.get('cf-connecting-ip')
      ?? request.headers.get('x-forwarded-for')
      ?? '127.0.0.1';
    await env.ALTERAN_DB.exec("CREATE TABLE IF NOT EXISTS rate_limit (ip TEXT NOT NULL, bucket TEXT NOT NULL, window INTEGER NOT NULL, count INTEGER NOT NULL, PRIMARY KEY (ip,bucket,window))");
    const results = await env.ALTERAN_DB.batch([
      env.ALTERAN_DB.prepare(
        'INSERT OR IGNORE INTO rate_limit (ip,bucket,window,count) VALUES (?,?,?,0)',
      ).bind(key, bucket, win),
      env.ALTERAN_DB.prepare(
        `UPDATE rate_limit
         SET count = count + ?
         WHERE ip = ? AND bucket = ? AND window = ? AND count + ? <= ?`,
      ).bind(cost, key, bucket, win, cost, limit),
    ]);
    if (changedRows(results[1]) !== 1) return rateLimited();
    const row: any = await env.ALTERAN_DB.prepare('SELECT count FROM rate_limit WHERE ip=? AND bucket=? AND window=?').bind(key, bucket, win).first();
    const count = row?.count ? Number(row.count) : cost;

    const headers = new Headers();
    headers.set('x-ratelimit-limit', String(limit));
    headers.set('x-ratelimit-remaining', String(Math.max(0, limit - count)));
    headers.set('x-ratelimit-window', '60s');

    return null;
  } catch {
    return null; // fail-open
  }
}

function changedRows(result: unknown): number {
  const meta = (result as { meta?: Record<string, unknown> } | undefined)?.meta;
  const changes = meta?.changes ?? meta?.rows_written ?? meta?.rowsWritten;
  return typeof changes === 'number' ? changes : 0;
}

function rateLimited() {
  return new Response(JSON.stringify({ error: 'RateLimited' }), {
    status: 429,
    headers: { 'Content-Type': 'application/json' },
  });
}
