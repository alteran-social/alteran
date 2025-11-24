import type { APIContext } from 'astro';
import { AuthTokenExpiredError, expiredToken, isAuthorized, unauthorized } from '../../lib/auth';

export const prerender = false;

export async function GET({ locals, request }: APIContext) {
  const { env } = locals.runtime;
  try {
    if (!(await isAuthorized(request, env))) return unauthorized();
  } catch (err) {
    if (err instanceof AuthTokenExpiredError) {
      return expiredToken();
    }
    throw err;
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
