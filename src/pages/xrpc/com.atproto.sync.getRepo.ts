import type { APIContext } from 'astro';
import { errorMessage } from '../../lib/errors';
import { invalidRequest, requireLocalDid } from '../../lib/local-xrpc';
import { buildRepoCar } from '../../services/car';

export const prerender = false;

/**
 * com.atproto.sync.getRepo
 * Returns a CAR snapshot of the repo for initial crawl/index.
 */
export async function GET({ locals, request }: APIContext) {
  const { env } = locals.runtime;
  const url = new URL(request.url);
  const did = requireLocalDid(env, url);
  if (!did.ok) return did.response;

  if (url.searchParams.has('since')) {
    return invalidRequest('Incremental getRepo CAR diffs are not supported by this single-user PDS');
  }

  try {
    const { bytes } = await buildRepoCar(env, did.value);
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(bytes);
        controller.close();
      },
    });
    return new Response(stream as any, {
      status: 200,
      headers: {
        // Official content type for CAR v1
        'Content-Type': 'application/vnd.ipld.car',
        'Cache-Control': 'no-store',
      },
    });
  } catch (error) {
    const msg = String(errorMessage(error) || error);
    // Map to lexicon-specified errors
    const known = ['RepoNotFound', 'RepoTakendown', 'RepoSuspended', 'RepoDeactivated'];
    const name = known.find((n) => msg.includes(n)) || (msg.includes('HeadNotFound') ? 'RepoNotFound' : null);
    if (name) {
      return new Response(JSON.stringify({ error: name, message: msg }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }
    console.error('getRepo (CAR) error:', error);
    return new Response(JSON.stringify({ error: 'InternalServerError', message: msg }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

// Avoid heavy CAR construction for HEAD. Respond with headers only.
export async function HEAD() {
  return new Response(null, {
    status: 200,
    headers: {
      'Content-Type': 'application/vnd.ipld.car',
      'Cache-Control': 'no-store',
    },
  });
}
