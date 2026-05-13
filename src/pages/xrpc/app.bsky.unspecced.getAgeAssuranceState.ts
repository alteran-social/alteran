import type { APIContext } from 'astro';
import { authErrorResponse, authenticateRequest, unauthorized } from '../../lib/auth';
import { canUseAppPasswordLevelAccess } from '../../lib/auth-scope';

export const prerender = false;

export async function GET({ locals, request }: APIContext) {
  const { env } = locals.runtime;
  try {
    const auth = await authenticateRequest(request, env);
    if (!auth || !canUseAppPasswordLevelAccess(auth.access)) return unauthorized();
  } catch (error) {
    const handled = await authErrorResponse(env, error);
    if (handled) return handled;
    throw error;
  }

  return new Response(
    JSON.stringify({
      status: 'unknown',
      lastInitiatedAt: new Date(0).toISOString(),
    }),
    {
      headers: { 'Content-Type': 'application/json' },
    },
  );
}
