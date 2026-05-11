import type { APIContext } from 'astro';
import { AuthTokenExpiredError, expiredToken, isAuthorized, unauthorized } from '../../lib/auth';
import { getActorPreferences } from '../../lib/preferences';

export const prerender = false;

export async function GET({ locals, request }: APIContext) {
  const { env } = locals.runtime;
  try {
    if (!(await isAuthorized(request, env))) return unauthorized();
  } catch (error) {
    if (error instanceof AuthTokenExpiredError) {
      return expiredToken();
    }
    throw error;
  }

  const { preferences } = await getActorPreferences(env);
  return new Response(JSON.stringify({ preferences: Array.isArray(preferences) ? preferences : [] }), {
    headers: { 'Content-Type': 'application/json' },
  });
}
