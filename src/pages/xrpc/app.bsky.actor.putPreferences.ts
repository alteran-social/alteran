import type { APIContext } from 'astro';
import { AuthTokenExpiredError, expiredToken, isAuthorized, unauthorized } from '../../lib/auth';
import { readJsonBounded } from '../../lib/util';
import { setActorPreferences } from '../../lib/preferences';

export const prerender = false;

export async function POST({ locals, request }: APIContext) {
  const { env } = locals.runtime;
  try {
    if (!(await isAuthorized(request, env))) return unauthorized();
  } catch (err) {
    if (err instanceof AuthTokenExpiredError) {
      return expiredToken();
    }
    throw err;
  }

  let body: any;
  try {
    body = await readJsonBounded(env, request);
  } catch (err: any) {
    if (err?.code === 'PayloadTooLarge') {
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
