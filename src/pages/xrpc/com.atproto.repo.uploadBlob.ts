import type { APIContext } from 'astro';
import { verifyResourceRequestHybrid, dpopResourceUnauthorized, handleResourceAuthError } from '../../lib/oauth/resource';
import { verifyServiceAuth, isServiceAuthToken } from '../../lib/service-auth';
import { checkRate } from '../../lib/ratelimit';
import { isAllowedMime, sniffMime, baseMime } from '../../lib/util';
import { R2BlobStore } from '../../services/r2-blob-store';
import { putBlobRef, checkBlobQuota, updateBlobQuota, isAccountActive } from '../../db/dal';
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
    } catch (err) {
      const handled = await handleResourceAuthError(env, err);
      if (handled) return handled;
      throw err;
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
  const headerMime = baseMime(request.headers.get('content-type'));
  const sniffed = sniffMime(buf);
  // Prefer sniffed MIME like upstream PDS; fall back to header
  const contentType = sniffed || headerMime;

  // Skip MIME type validation during migration - accept all types
  // Uncomment to enforce: if (!isAllowedMime(env, contentType)) return new Response(JSON.stringify({ error: 'UnsupportedMediaType' }), { status: 415 });

  // Check quota before upload
  const canUpload = await checkBlobQuota(env, did, buf.byteLength);
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
    const res = await store.put(buf, { contentType });

    // Compute a CIDv1 (raw) for the blob so clients receive a valid CID link
    const digest = await sha256.digest(new Uint8Array(buf));
    const cid = CID.createV1(0x55, digest); // 0x55 = raw codec
    const cidStr = cid.toString();

    // Register blob ref with CID-based key
    await putBlobRef(env, did, cidStr, res.key, contentType, res.size);

    // Update quota
    await updateBlobQuota(env, did, res.size, 1);

    // Mirror upstream shape exactly; helpful debugging header
    // Conform to lexicon: blob object must include $type: 'blob'
    const body = { blob: { $type: 'blob', ref: { $link: cidStr }, mimeType: contentType, size: res.size } };
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    // Debug-only headers (safe for clients to ignore)
    headers['x-sniffed-mime'] = sniffed || '';
    headers['x-header-mime'] = headerMime;
    if (enc) headers['x-upload-encoding'] = enc;

    return new Response(JSON.stringify(body), { headers });
  } catch (e: any) {
    if (String(e.message || '').startsWith('BlobTooLarge')) return new Response(JSON.stringify({ error: 'PayloadTooLarge' }), { status: 413 });
    return new Response(JSON.stringify({ error: 'UploadFailed' }), { status: 500 });
  }
}
