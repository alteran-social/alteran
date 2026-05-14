import type { APIContext } from 'astro';
import { debugNotFound, isDebugRouteAllowed } from '../../lib/debug-routes';
import { errorMessage } from '../../lib/errors';

export const prerender = false;

export async function GET({ locals, request }: APIContext) {
  const { env } = locals.runtime;
  if (!isDebugRouteAllowed(env, request)) return debugNotFound();

  if (!env.ALTERAN_SEQUENCER) {
    return new Response(JSON.stringify({ error: 'SequencerNotConfigured' }), {
      status: 503,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  try {
    const id = env.ALTERAN_SEQUENCER.idFromName('default');
    const stub = env.ALTERAN_SEQUENCER.get(id);
    const response = await stub.fetch(new Request('http://internal/metrics') as any);
    const text = await response.text();
    return new Response(text, { status: response.status, headers: { 'Content-Type': 'application/json' } });
  } catch (e) {
    return new Response(JSON.stringify({ error: 'InternalError', message: String(errorMessage(e) || e) }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}
