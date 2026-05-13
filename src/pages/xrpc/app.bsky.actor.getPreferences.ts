import type { APIContext } from 'astro';
import { authErrorResponse, authenticateRequest, unauthorized } from '../../lib/auth';
import { canAccessActorPreferences } from '../../lib/auth-scope';
import { getActorPreferences } from '../../lib/preferences';

export const prerender = false;

export async function GET({ locals, request }: APIContext) {
  const { env } = locals.runtime;
  try {
    const auth = await authenticateRequest(request, env);
    if (!auth || !canAccessActorPreferences(auth.access)) return unauthorized();
  } catch (error) {
    const handled = await authErrorResponse(env, error);
    if (handled) return handled;
    throw error;
  }

  const { preferences } = await getActorPreferences(env);
  return new Response(JSON.stringify({ preferences: Array.isArray(preferences) ? preferences : [] }), {
    headers: { 'Content-Type': 'application/json' },
  });
}
