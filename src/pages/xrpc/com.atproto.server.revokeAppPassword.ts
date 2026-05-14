import type { APIContext } from 'astro';
import { readJson } from '../../lib/util';
import { authenticateRequest } from '../../lib/auth';
import { canAccessFullAccount } from '../../lib/auth-scope';
import { deleteAppPasswordRow, revokeRefreshTokensByAppPasswordName } from '../../db/app-password';

export const prerender = false;

export async function POST({ locals, request }: APIContext) {
  const { env } = locals;
  const auth = await authenticateRequest(request, env).catch(() => null);
  if (!auth || !canAccessFullAccount(auth.access)) {
    return new Response(JSON.stringify({ error: 'AuthRequired', message: 'Full-access session required' }), {
      status: 401, headers: { 'Content-Type': 'application/json' },
    });
  }
  const raw = await readJson(request).catch(() => ({}));
  const body = (raw ?? {}) as { name?: unknown };
  const name = typeof body.name === 'string' ? body.name.trim() : '';
  if (!name) {
    return new Response(JSON.stringify({ error: 'InvalidRequest', message: 'name is required' }), {
      status: 400, headers: { 'Content-Type': 'application/json' },
    });
  }
  const did = auth.claims.sub;
  // Revoke before deleting so the deletion is the final visible step. If we
  // deleted first, a concurrent refresh could observe the row, complete a
  // rotation, and store its new refresh row *after* the revoke sweep —
  // letting the new token escape revocation.
  await revokeRefreshTokensByAppPasswordName(env, did, name);
  const removed = await deleteAppPasswordRow(env, did, name);
  if (!removed) {
    return new Response(JSON.stringify({ error: 'InvalidRequest', message: 'app password not found' }), {
      status: 400, headers: { 'Content-Type': 'application/json' },
    });
  }
  return new Response(JSON.stringify({}), { headers: { 'Content-Type': 'application/json' } });
}
