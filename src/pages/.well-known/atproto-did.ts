import type { APIContext } from 'astro';
import { configuredDid, requestMatchesConfiguredHandle } from '../../lib/public-host';

export const prerender = false;

export async function GET({ locals, request }: APIContext) {
  const { env } = locals.runtime;

  if (!await requestMatchesConfiguredHandle(request, env)) {
    return new Response('NotFound', {
      status: 404,
      headers: { 'Content-Type': 'text/plain' },
    });
  }

  return new Response(await configuredDid(env), {
    headers: { 'Content-Type': 'text/plain' },
  });
}
