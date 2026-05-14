import type { APIContext } from 'astro';
import { ensureValidDid } from '@atproto/syntax';
import { CID } from 'multiformats/cid';
import { getDb } from '../../db/client';
import { blob_ref } from '../../db/schema';
import { and, eq } from 'drizzle-orm';
import { blobKeyHasUsage, isAccountActive } from '../../db/dal';
import { resolveSecret } from '../../lib/secrets';

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
    const configuredDid = await resolveSecret(env.PDS_DID);
    const did = url.searchParams.get('did');
    const cid = url.searchParams.get('cid');
    if (!did || !cid) {
      return jsonError('InvalidRequest', 'did and cid parameters are required');
    }
    if (!isValidDid(did) || !isValidCid(cid)) {
      return jsonError('InvalidRequest', 'did and cid parameters must be valid');
    }
    if (!configuredDid || did !== configuredDid) {
      return jsonError('RepoNotFound', 'Repo not found');
    }

    const active = await isAccountActive(env, did);
    if (!active) {
      return jsonError('RepoDeactivated', 'Repo is deactivated');
    }

    const db = getDb(env);

    const blobMeta = await db
      .select()
      .from(blob_ref)
      .where(and(eq(blob_ref.did, did), eq(blob_ref.cid, cid)))
      .get();

    if (!blobMeta || !(await blobKeyHasUsage(env, did, blobMeta.key))) {
      return blobNotFound();
    }

    // Fetch blob from R2
    const r2 = env.ALTERAN_BLOBS;
    const object = await r2.get(blobMeta.key);

    if (!object || object.size !== Number(blobMeta.size)) {
      return blobNotFound();
    }

    const body = await responseBody(object);
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

function blobNotFound(): Response {
  return jsonError('BlobNotFound', 'Blob not found');
}

function jsonError(error: string, message: string, status = 400): Response {
  return new Response(
    JSON.stringify({ error, message }),
    { status, headers: { 'Content-Type': 'application/json' } },
  );
}

function isValidDid(did: string): boolean {
  try {
    ensureValidDid(did);
    return true;
  } catch {
    return false;
  }
}

function isValidCid(cid: string): boolean {
  try {
    CID.parse(cid);
    return true;
  } catch {
    return false;
  }
}

async function responseBody(object: {
  body: unknown;
  arrayBuffer(): Promise<ArrayBuffer>;
}): Promise<BodyInit> {
  if ('Bun' in globalThis) {
    // Direct Miniflare tests expose R2 bodies through a workerd object that
    // cannot be read as a stream from Bun. Workers production takes the stream
    // path below.
    return object.arrayBuffer();
  }
  try {
    return localReadableStream(object.body as ReadableStream<Uint8Array>);
  } catch (error) {
    if (error instanceof Error && error.message.includes('can not be cloned')) {
      return object.arrayBuffer();
    }
    throw error;
  }
}

function localReadableStream(source: ReadableStream<Uint8Array>): ReadableStream<Uint8Array> {
  const reader = source.getReader();
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      try {
        const chunk = await reader.read();
        if (chunk.done) {
          controller.close();
          return;
        }
        controller.enqueue(new Uint8Array(chunk.value));
      } catch (error) {
        controller.error(error);
      }
    },
    cancel(reason) {
      return reader.cancel(reason);
    },
  });
}
