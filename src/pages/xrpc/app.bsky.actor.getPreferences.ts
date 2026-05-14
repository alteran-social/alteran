import type { APIContext } from 'astro';
import { authErrorResponse, authenticateRequest, unauthorized } from '../../lib/auth';
import { canAccessActorPreferences } from '../../lib/auth-scope';
import { preferencesForAccess } from '../../lib/preference-policy';
import { getActorPreferences } from '../../lib/preferences';

export const prerender = false;

export async function GET({ locals, request }: APIContext) {
  const { env } = locals;
  let auth: NonNullable<Awaited<ReturnType<typeof authenticateRequest>>>;
  try {
    const verified = await authenticateRequest(request, env);
    if (!verified || !canAccessActorPreferences(verified.access)) return unauthorized();
    auth = verified;
  } catch (error) {
    const handled = await authErrorResponse(env, error);
    if (handled) return handled;
    throw error;
  }

  const { preferences } = await getActorPreferences(env);
  const visible = preferencesForAccess(Array.isArray(preferences) ? preferences : [], auth.access);
  return new Response(JSON.stringify({ preferences: visible }), {
    headers: { 'Content-Type': 'application/json' },
  });
}
