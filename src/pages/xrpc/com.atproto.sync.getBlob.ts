import type { APIContext } from 'astro';
import { getDb } from '../../db/client';
import { blob_ref } from '../../db/schema';
import { and, eq } from 'drizzle-orm';
import { blobKeyHasUsage, isAccountActive } from '../../db/dal';

export const prerender = false;

/**
 * com.atproto.sync.getBlob
 *
 * Serves a blob by its CID. Used during migration to transfer blobs
 * from the old PDS to the new PDS.
 *
 * Query params:
 * - did: The DID of the account (optional, defaults to configured PDS_DID)
 * - cid: The CID of the blob to retrieve (required)
 */
export async function GET({ locals, url }: APIContext) {
  const { env } = locals.runtime;

  try {
    const configuredDid = typeof env.PDS_DID === 'string' ? env.PDS_DID : undefined;
    const did = url.searchParams.get('did') ?? configuredDid;
    const cid = url.searchParams.get('cid');
    if (!did || !cid) {
      return new Response(
        JSON.stringify({
          error: 'InvalidRequest',
          message: 'did and cid parameters are required'
        }),
        { status: 400, headers: { 'Content-Type': 'application/json' } }
      );
    }

    const active = await isAccountActive(env, did);
    if (!active) {
      return new Response(
        JSON.stringify({ error: 'AccountInactive', message: 'Account is not active' }),
        { status: 403, headers: { 'Content-Type': 'application/json' } }
      );
    }

    const db = getDb(env);

    const blobMeta = await db
      .select()
      .from(blob_ref)
      .where(and(eq(blob_ref.did, did), eq(blob_ref.cid, cid)))
      .get();

    if (!blobMeta || !(await blobKeyHasUsage(env, did, blobMeta.key))) {
      return new Response(
        JSON.stringify({ error: 'InvalidRequest', message: 'Blob not found' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } }
      );
    }

    // Fetch blob from R2
    const r2 = env.ALTERAN_BLOBS;
    const object = await r2.get(blobMeta.key);

    if (!object) {
      return new Response(
        JSON.stringify({ error: 'InvalidRequest', message: 'Blob not found' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } }
      );
    }

    const body = await object.arrayBuffer();
    return new Response(body, {
      status: 200,
      headers: {
        'Content-Type': blobMeta.mime,
        'Content-Length': String(blobMeta.size),
        'Cache-Control': 'public, max-age=31536000, immutable',
        'x-content-type-options': 'nosniff',
        'content-security-policy': "default-src 'none'; sandbox",
      },
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Failed to retrieve blob';
    return new Response(
      JSON.stringify({
        error: 'InternalServerError',
        message,
      }),
      { status: 500, headers: { 'Content-Type': 'application/json' } }
    );
  }
}
