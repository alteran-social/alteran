import type { APIContext } from 'astro';
import { getAppViewConfig } from '../../lib/appview';
import { configuredAtprotoHandle, configuredDid, validAtprotoHandle } from '../../lib/public-host';

export const prerender = false;

/**
 * com.atproto.identity.resolveHandle
 * Resolve a handle to a DID
 */
export async function GET({ locals, url }: APIContext) {
  const { env } = locals;

  const handle = url.searchParams.get('handle');

  if (!handle) {
    return new Response(
      JSON.stringify({ error: 'InvalidRequest', message: 'handle parameter required' }),
      { status: 400, headers: { 'Content-Type': 'application/json' } }
    );
  }

  const normalizedHandle = validAtprotoHandle(handle);
  if (!normalizedHandle) {
    return new Response(
      JSON.stringify({ error: 'InvalidRequest', message: 'Unable to resolve handle' }),
      { status: 400, headers: { 'Content-Type': 'application/json' } },
    );
  }

  // Single-user PDS: resolve the local configured handle directly
  const configuredHandle = await configuredAtprotoHandle(env);
  if (configuredHandle && normalizedHandle === configuredHandle) {
    return new Response(
      JSON.stringify({ did: await configuredDid(env) }),
      {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }
    );
  }

  // For non-local handles, mirror upstream PDS behavior:
  // proxy the resolution to the configured AppView (or api.bsky.app by default).
  try {
    const app = getAppViewConfig(env);
    const base = app?.url || 'https://api.bsky.app';
    const upstream = new URL('/xrpc/com.atproto.identity.resolveHandle', base);
    upstream.searchParams.set('handle', normalizedHandle);

    const response = await fetch(upstream.toString(), {
      headers: { accept: 'application/json' },
    });

    if (response.ok) {
      // Pass through upstream JSON (e.g. { did })
      return new Response(await response.text(), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Map upstream failures to the standard InvalidRequest shape used by PDS
    const text = await response.text().catch(() => '');
    const body = text ? (() => { try { return JSON.parse(text); } catch { return null; } })() : null;
    const message = body?.message || 'Unable to resolve handle';
    return new Response(
      JSON.stringify({ error: 'InvalidRequest', message }),
      { status: 400, headers: { 'Content-Type': 'application/json' } }
    );
  } catch {
    return new Response(
      JSON.stringify({ error: 'InvalidRequest', message: 'Unable to resolve handle' }),
      { status: 400, headers: { 'Content-Type': 'application/json' } }
    );
  }
}
