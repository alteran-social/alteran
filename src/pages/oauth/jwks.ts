import type { APIContext } from 'astro';
import { getAuthorizationServerPublicJwk } from '../../lib/oauth/as-keys';

export const prerender = false;

export async function GET({ locals }: APIContext) {
  const { env } = locals;
  const jwk = await getAuthorizationServerPublicJwk(env);
  return new Response(JSON.stringify({ keys: [jwk] }, null, 2), {
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'public, max-age=300',
    },
  });
}
