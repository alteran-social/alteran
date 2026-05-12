import type { APIContext } from 'astro';
import { errorCode, errorMessage } from '../../lib/errors';
import { authErrorResponse, isAuthorized, unauthorized } from '../../lib/auth';
import { readJsonBounded } from '../../lib/util';
import { setActorPreferences } from '../../lib/preferences';

export const prerender = false;

export async function POST({ locals, request }: APIContext) {
  const { env } = locals.runtime;
  try {
    if (!(await isAuthorized(request, env))) return unauthorized();
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
  await setActorPreferences(env, preferences);

  return new Response(JSON.stringify({}), {
    headers: { 'Content-Type': 'application/json' },
  });
}
