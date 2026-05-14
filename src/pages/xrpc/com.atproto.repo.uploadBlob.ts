import type { APIContext } from 'astro';
import { errorMessage } from '../../lib/errors';
import { verifyResourceRequestHybrid, dpopResourceUnauthorized, handleResourceAuthError, insufficientScopeResponse } from '../../lib/oauth/resource';
import { canUploadBlob } from '../../lib/auth-scope';
import { verifyServiceAuth, isServiceAuthToken } from '../../lib/service-auth';
import { checkRate } from '../../lib/ratelimit';
import { isAllowedMime, sniffMime, baseMime } from '../../lib/util';
import { R2BlobStore } from '../../services/r2-blob-store';
import { putBlobRef, checkBlobQuota, updateBlobQuota, isAccountActive, blobKeyHasUsage } from '../../db/dal';
import { resolveSecret } from '../../lib/secrets';
import { CID } from 'multiformats/cid';
import { sha256 } from 'multiformats/hashes/sha2';

export const prerender = false;

export async function POST({ locals, request }: APIContext) {
  const { env } = locals.runtime;
  
  // Check if this is a service auth request (from video.bsky.app, etc.)
  const authHeader = request.headers.get('authorization');
  const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7).trim() : null;
  
  let isServiceAuth = false;
  let authAccess: Awaited<ReturnType<typeof verifyResourceRequestHybrid>> | null = null;
  if (token && isServiceAuthToken(token)) {
    const serviceAuth = await verifyServiceAuth(env, request);
    if (serviceAuth) {
      isServiceAuth = true;
    } else {
      return new Response(
        JSON.stringify({ error: 'AuthRequired', message: 'Invalid service auth token' }),
        { status: 401, headers: { 'Content-Type': 'application/json' } }
      );
    }
  }

  // If not service auth, verify as user request
  if (!isServiceAuth) {
    try {
      const auth = await verifyResourceRequestHybrid(env, request);
      if (!auth) return dpopResourceUnauthorized(env);
      authAccess = auth;
    } catch (error) {
      const handled = await handleResourceAuthError(env, error);
      if (handled) return handled;
      throw error;
    }
  }

  // Get DID from environment (single-user PDS)
  const did = (await resolveSecret(env.PDS_DID)) ?? 'did:example:single-user';

  // Check if account is active
  const active = await isAccountActive(env, did);
  if (!active) {
    return new Response(
      JSON.stringify({
        error: 'AccountDeactivated',
        message: 'Account is deactivated. Activate it before uploading blobs.'
      }),
      { status: 403, headers: { 'Content-Type': 'application/json' } }
    );
  }

  const rateLimitResponse = await checkRate(env, request, 'blob');
  if (rateLimitResponse) return rateLimitResponse;

  // Decompress if Content-Encoding is present (some clients may compress uploads)
  const enc = (request.headers.get('content-encoding') || '').toLowerCase();
  let buf: ArrayBuffer;
  if (enc && (enc === 'gzip' || enc === 'br' || enc === 'deflate')) {
    try {
      // @ts-ignore: DecompressionStream is available in CF Workers runtime
      const ds = new DecompressionStream(enc);
      const decompressed = request.body?.pipeThrough(ds);
      buf = await new Response(decompressed).arrayBuffer();
    } catch {
      // Fallback to raw body if decompression not supported
      buf = await request.arrayBuffer();
    }
  } else {
    buf = await request.arrayBuffer();
  }
  const declaredLength = request.headers.get('content-length');
  if (!enc && declaredLength !== null) {
    const expectedLength = Number(declaredLength);
    if (!Number.isFinite(expectedLength) || expectedLength !== buf.byteLength) {
      return new Response(
        JSON.stringify({ error: 'InvalidRequest', message: 'Content-Length does not match body size' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      );
    }
  }
  const headerMime = baseMime(request.headers.get('content-type'));
  const sniffed = sniffMime(buf);
  // Prefer sniffed MIME like upstream PDS; fall back to header
  const contentType = sniffed || headerMime;

  if (!isAllowedMime(env, contentType)) {
    return new Response(
      JSON.stringify({ error: 'UnsupportedMediaType', message: 'Unsupported blob MIME type' }),
      { status: 415, headers: { 'Content-Type': 'application/json' } },
    );
  }
  if (!isServiceAuth && authAccess && !canUploadBlob(authAccess.access, contentType)) {
    return insufficientScopeResponse();
  }

  // Compute the protocol CID before writing so duplicate uploads can be a
  // metadata no-op, matching the PDS blob lifecycle.
  const digest = await sha256.digest(new Uint8Array(buf));
  const cid = CID.createV1(0x55, digest); // 0x55 = raw codec
  const cidStr = cid.toString();
  const existing = await env.ALTERAN_DB.prepare(
    `SELECT key, mime, size, state, takedown_ref
     FROM blob
     WHERE did = ? AND cid = ?
     LIMIT 1`,
  )
    .bind(did, cidStr)
    .first<{ key: string; mime: string; size: number; state: string; takedown_ref: string | null }>();

  const existingHasUsage = existing
    ? await blobKeyHasUsage(env, did, existing.key)
    : false;
  if (existing?.state === 'permanent' && existing.takedown_ref === null && existingHasUsage) {
    return blobUploadResponse(
      cidStr,
      existing.mime,
      Number(existing.size),
      sniffed,
      headerMime,
      enc,
    );
  }

  // Check quota before upload
  const quotaBytes = existing ? 0 : buf.byteLength;
  const canUpload = await checkBlobQuota(env, did, quotaBytes);
  if (!canUpload) {
    return new Response(
      JSON.stringify({
        error: 'BlobQuotaExceeded',
        message: 'Blob storage quota exceeded'
      }),
      { status: 413 }
    );
  }

  const store = new R2BlobStore(env);
  try {
    const response = await store.put(buf, { contentType });

    if (existing?.state === 'permanent' && !existingHasUsage) {
      await env.ALTERAN_DB.prepare(
        `UPDATE blob
         SET state = 'temp'
         WHERE did = ?
           AND cid = ?
           AND takedown_ref IS NULL
           AND NOT EXISTS (
             SELECT 1 FROM blob_usage
             WHERE blob_usage.did = blob.did
               AND blob_usage.key = blob.key
           )`,
      ).bind(did, cidStr).run();
    }

    // Register blob ref with CID-based key
    await putBlobRef(env, did, cidStr, response.key, contentType, response.size);

    // Update quota
    if (!existing) await updateBlobQuota(env, did, response.size, 1);

    return blobUploadResponse(cidStr, contentType, response.size, sniffed, headerMime, enc);
  } catch (e) {
    if (String(errorMessage(e) || '').startsWith('BlobTooLarge')) return new Response(JSON.stringify({ error: 'PayloadTooLarge' }), { status: 413 });
    return new Response(JSON.stringify({ error: 'UploadFailed' }), { status: 500 });
  }
}

function blobUploadResponse(
  cid: string,
  mimeType: string,
  size: number,
  sniffed: string | null,
  headerMime: string,
  enc: string,
): Response {
  // Mirror upstream shape exactly; helpful debugging headers are safe for clients to ignore.
  const body = { blob: { $type: 'blob', ref: { $link: cid }, mimeType, size } };
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  headers['x-sniffed-mime'] = sniffed || '';
  headers['x-header-mime'] = headerMime;
  if (enc) headers['x-upload-encoding'] = enc;
  return new Response(JSON.stringify(body), { headers });
}
