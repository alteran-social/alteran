import type { APIContext } from 'astro';
import { readJson } from '../../lib/util';

export const prerender = false;

/**
 * com.atproto.identity.updateHandle
 * Update the handle for the repository
 */
export async function POST({ locals, request }: APIContext) {
  const { env } = locals.runtime;

  try {
    const body = (await readJson(request)) as { handle?: string };
    const { handle } = body;

    if (!handle) {
      return new Response(
        JSON.stringify({ error: 'InvalidRequest', message: 'handle required' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } }
      );
    }

    // TODO: Implement handle verification (DNS TXT or HTTP)
    // TODO: Update PDS_HANDLE configuration
    // For single-user PDS, this would require redeployment with new config

    return new Response(
      JSON.stringify({
        error: 'NotImplemented',
        message: 'Handle updates require PDS reconfiguration for single-user mode',
      }),
      {
        status: 501,
        headers: { 'Content-Type': 'application/json' },
      }
    );
  } catch (error) {
    console.error('updateHandle error:', error);
    return new Response(
      JSON.stringify({ error: 'InternalServerError', message: String(error) }),
      { status: 500, headers: { 'Content-Type': 'application/json' } }
    );
  }
}
