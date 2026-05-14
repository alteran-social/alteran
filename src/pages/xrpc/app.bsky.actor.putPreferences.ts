import type { APIContext } from 'astro';
import { errorCode, errorMessage } from '../../lib/errors';
import { authErrorResponse, authenticateRequest, unauthorized } from '../../lib/auth';
import { canAccessActorPreferences } from '../../lib/auth-scope';
import { hasAppPasswordRestrictedPreferences, preferencesForWrite } from '../../lib/preference-policy';
import { readJsonBounded } from '../../lib/util';
import { getActorPreferences, setActorPreferences } from '../../lib/preferences';

export const prerender = false;

export async function POST({ locals, request }: APIContext) {
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

  let body: any;
  try {
    body = await readJsonBounded(env, request);
  } catch (error) {
    if (errorCode(error) === 'PayloadTooLarge') {
      return new Response(JSON.stringify({ error: 'PayloadTooLarge' }), { status: 413 });
    }
    return new Response(JSON.stringify({ error: 'BadRequest' }), { status: 400 });
  }

  const preferences = Array.isArray(body?.preferences) ? body.preferences : [];
  if (hasAppPasswordRestrictedPreferences(preferences, auth.access)) {
    return new Response(
      JSON.stringify({ error: 'Forbidden', message: 'App passwords cannot update restricted preferences' }),
      { status: 403, headers: { 'Content-Type': 'application/json' } },
    );
  }
  const existing = auth.access.isAppPassword ? (await getActorPreferences(env)).preferences : [];
  const writable = preferencesForWrite(existing, preferences, auth.access);
  await setActorPreferences(env, writable);

  return new Response(JSON.stringify({}), {
    headers: { 'Content-Type': 'application/json' },
  });
}
