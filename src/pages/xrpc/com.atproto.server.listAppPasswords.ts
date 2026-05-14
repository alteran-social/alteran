import type { APIContext } from 'astro';
import type { Env } from '../../env';
import { authErrorResponse, authenticateRequest, unauthorized } from '../../lib/auth';
import { canAccessFullAccount } from '../../lib/auth-scope';
import { jsonError } from '../../lib/repo-write-validation';
import { listAppPasswords } from '../../db/account';

export const prerender = false;

export async function GET({ locals, request }: APIContext) {
  const { env } = locals.runtime;
  const auth = await authenticateFullAccount(env, request);
  if (auth instanceof Response) return auth;

  const rows = await listAppPasswords(env, auth.claims.sub);
  return new Response(
    JSON.stringify({
      passwords: rows.map((row) => ({
        name: row.name,
        createdAt: new Date(row.createdAt).toISOString(),
        privileged: !!row.privileged,
      })),
    }),
    { headers: { 'Content-Type': 'application/json' } },
  );
}

async function authenticateFullAccount(env: Env, request: Request) {
  let auth;
  try {
    auth = await authenticateRequest(request, env);
  } catch (error) {
    const handled = await authErrorResponse(env, error);
    if (handled) return handled;
    throw error;
  }
  if (!auth) return unauthorized();
  if (auth.access.isTakendown) {
    return jsonError('AccountTakedown', 'Account has been taken down', 403);
  }
  if (!canAccessFullAccount(auth.access)) return unauthorized();
  return auth;
}
