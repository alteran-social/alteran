import type { APIContext } from 'astro';
import { authenticateRequest } from '../../lib/auth';
import { canAccessFullAccount } from '../../lib/auth-scope';
import { listAppPasswordRows } from '../../db/app-password';

export const prerender = false;

export async function GET({ locals, request }: APIContext) {
  const { env } = locals;
  const auth = await authenticateRequest(request, env).catch(() => null);
  if (!auth || !canAccessFullAccount(auth.access)) {
    return new Response(JSON.stringify({ error: 'AuthRequired', message: 'Full-access session required' }), {
      status: 401, headers: { 'Content-Type': 'application/json' },
    });
  }
  const rows = await listAppPasswordRows(env, auth.claims.sub);
  return new Response(JSON.stringify({
    passwords: rows.map((row) => ({
      name: row.name,
      privileged: row.privileged,
      createdAt: new Date(row.createdAt * 1000).toISOString(),
    })),
  }), { headers: { 'Content-Type': 'application/json' } });
}
