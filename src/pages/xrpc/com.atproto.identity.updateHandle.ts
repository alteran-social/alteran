import type { APIContext } from 'astro';
export const prerender = false;

/**
 * com.atproto.identity.updateHandle
 * Update the handle for the repository
 */
export async function POST({ locals, request }: APIContext) {
  void locals;
  void request;
  return new Response(
    JSON.stringify({
      error: 'NotImplemented',
      message: 'Handle updates require PDS reconfiguration for single-user mode',
    }),
    {
      status: 501,
      headers: { 'Content-Type': 'application/json' },
    },
  );
}
