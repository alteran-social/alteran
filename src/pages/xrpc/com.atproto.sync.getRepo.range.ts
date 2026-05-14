import type { APIContext } from 'astro';
import { buildRepoCarRange } from '../../services/car';

export const prerender = false;

/**
 * Non-standard helper route used by tests to stream a CAR by commit seq range.
 * Query: ?from=<seq>&to=<seq>
 */
export async function GET({ locals, request }: APIContext) {
  const { env } = locals;
  const url = new URL(request.url);

  const fromParam = url.searchParams.get('from');
  const toParam = url.searchParams.get('to');

  const fromSeq = parseInt(String(fromParam ?? ''), 10);
  const toSeq = parseInt(String(toParam ?? ''), 10);

  if (!Number.isFinite(fromSeq) || !Number.isFinite(toSeq) || fromSeq < 0 || toSeq < fromSeq) {
    return new Response(
      JSON.stringify({ error: 'InvalidRequest', message: 'Provide valid numeric from <= to' }),
      { status: 400, headers: { 'Content-Type': 'application/json' } },
    );
  }

  const car = await buildRepoCarRange(env, fromSeq, toSeq);
  return new Response(car.bytes as any, {
    headers: {
      'Content-Type': 'application/vnd.ipld.car; version=1',
      'Content-Disposition': 'inline; filename="repo-range.car"',
    },
  });
}
