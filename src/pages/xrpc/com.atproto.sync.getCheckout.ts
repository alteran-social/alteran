import type { APIContext } from 'astro';
import { buildRepoCar, buildRepoCarRange } from '../../services/car';

export const prerender = false;

export async function GET({ locals, request }: APIContext) {
  const { env } = locals;
  const url = new URL(request.url);
  const did = url.searchParams.get('did') ?? (env.PDS_DID as string);

  // Support commit range queries
  const fromParam = url.searchParams.get('from');
  const toParam = url.searchParams.get('to');

  let car;
  if (fromParam && toParam) {
    // Return commits in range [from, to]
    const fromSeq = parseInt(fromParam, 10);
    const toSeq = parseInt(toParam, 10);

    if (isNaN(fromSeq) || isNaN(toSeq) || fromSeq < 0 || toSeq < fromSeq) {
      return new Response(
        JSON.stringify({
          error: 'InvalidRequest',
          message: 'Invalid commit range: from and to must be valid sequence numbers with from <= to'
        }),
        { status: 400, headers: { 'Content-Type': 'application/json' } }
      );
    }

    car = await buildRepoCarRange(env, fromSeq, toSeq);
  } else {
    // Return full repo snapshot
    car = await buildRepoCar(env, did);
  }

  return new Response(car.bytes as any, {
    headers: {
      'Content-Type': 'application/vnd.ipld.car; version=1',
      'Content-Disposition': 'inline; filename="checkout.car"',
    },
  });
}
