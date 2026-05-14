import type { APIContext } from 'astro';
import { invalidRequest, requireLocalDid } from '../../lib/local-xrpc';
import { buildRepoCar } from '../../services/car';

export const prerender = false;

export async function GET({ locals, request }: APIContext) {
  const { env } = locals.runtime;
  const url = new URL(request.url);
  const did = requireLocalDid(env, url);
  if (!did.ok) return did.response;

  if (url.searchParams.has('from') || url.searchParams.has('to')) {
    return invalidRequest('getCheckout does not support commit range parameters');
  }

  const car = await buildRepoCar(env, did.value);

  return new Response(car.bytes as any, {
    headers: {
      'Content-Type': 'application/vnd.ipld.car; version=1',
      'Content-Disposition': 'inline; filename="checkout.car"',
    },
  });
}
