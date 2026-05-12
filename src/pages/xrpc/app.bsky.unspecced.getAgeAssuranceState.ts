import type { APIContext } from 'astro';
import { authErrorResponse, isAuthorized, unauthorized } from '../../lib/auth';

export const prerender = false;

export async function GET({ locals, request }: APIContext) {
  const { env } = locals.runtime;
  try {
    if (!(await isAuthorized(request, env))) return unauthorized();
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
