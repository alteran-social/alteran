import type { APIContext } from 'astro';
import { getDb } from '../../db/client';
import { blob_ref } from '../../db/schema';
import { and, eq } from 'drizzle-orm';
import { isAccountActive } from '../../db/dal';
import { requireCid, requireLocalDid, xrpcError } from '../../lib/local-xrpc';

export const prerender = false;

/**
 * com.atproto.sync.getBlob
 *
 * Serves a blob by its CID. Used during migration to transfer blobs
 * from the old PDS to the new PDS.
 *
 * Query params:
 * - did: The DID of the account (required)
 * - cid: The CID of the blob to retrieve (required)
 */
export async function GET({ locals, url }: APIContext) {
  const { env } = locals.runtime;

  try {
    const did = requireLocalDid(env, url);
    if (!did.ok) return did.response;

    const cidParam = requireCid(url);
    if (!cidParam.ok) return cidParam.response;
    const cid = cidParam.value.toString();

    const active = await isAccountActive(env, did.value);
    if (!active) {
      return xrpcError('RepoDeactivated', 'Repo is not active');
    }

    const db = getDb(env);

    // Look up blob metadata by CID
    let blobMeta = await db
      .select()
      .from(blob_ref)
      .where(and(eq(blob_ref.did, did.value), eq(blob_ref.cid, cid)))
      .get();

    if (!blobMeta) {
      return xrpcError('BlobNotFound', 'Blob not found');
    }

    const { key, mime, size } = blobMeta;

    // Fetch blob from R2
    const r2 = env.ALTERAN_BLOBS;
    const object = await r2.get(key);

    if (!object) {
      return xrpcError('BlobNotFound', 'Blob not found');
    }

    const body = await object.arrayBuffer();
    return new Response(body, {
      status: 200,
      headers: {
        'Content-Type': mime,
        ...(size != null ? { 'Content-Length': String(size) } : {}),
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
