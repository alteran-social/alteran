import type { APIContext } from 'astro';
import { requireLocalDid, requireNsid, requireRecordKey } from '../../lib/local-xrpc';
import { buildRecordProofCar } from '../../services/car';

export const prerender = false;

/**
 * com.atproto.sync.getRecord
 * Get a single record as a CAR file
 */
export async function GET({ locals, url }: APIContext) {
  const { env } = locals.runtime;

  const did = requireLocalDid(env, url);
  if (!did.ok) return did.response;

  const collection = requireNsid(url);
  if (!collection.ok) return collection.response;

  const rkey = requireRecordKey(url);
  if (!rkey.ok) return rkey.response;

  try {
    const { bytes } = await buildRecordProofCar(env as any, did.value, collection.value, rkey.value);
    return new Response(bytes as any, {
      status: 200,
      headers: {
        'Content-Type': 'application/vnd.ipld.car; version=1',
        'Content-Disposition': 'inline; filename="record-proof.car"',
      },
    });
  } catch (error) {
    console.error('getRecord error:', error);
    return new Response(
      JSON.stringify({ error: 'InternalServerError', message: String(error) }),
      { status: 500, headers: { 'Content-Type': 'application/json' } }
    );
  }
}
