import type { APIContext } from 'astro';
import type { Env } from '../../env';
import { errorMessage } from '../../lib/errors';
import { verifyResourceRequestHybrid, dpopResourceUnauthorized, handleResourceAuthError, insufficientScopeResponse } from '../../lib/oauth/resource';
import { canUploadBlob } from '../../lib/auth-scope';
import { verifyServiceAuth, isServiceAuthToken } from '../../lib/service-auth';
import { checkRate } from '../../lib/ratelimit';
import { sniffMime, baseMime } from '../../lib/util';
import {
  deleteUnreferencedBlobRef,
  isAccountActive,
  registerBlobRefWithQuota,
  sweepEligibleUnreferencedBlobKeys,
} from '../../db/dal';
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
      if (!canUploadBlob(auth.access, baseMime(request.headers.get('content-type')))) {
        return insufficientScopeResponse();
      }
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
  const headerMime = baseMime(request.headers.get('content-type'));
  const sniffed = sniffMime(buf);
  // Prefer sniffed MIME like upstream PDS; fall back to header
  const contentType = sniffed || headerMime;

  // Skip MIME type validation during migration - accept all types
  // Uncomment to enforce: if (!isAllowedMime(env, contentType)) return new Response(JSON.stringify({ error: 'UnsupportedMediaType' }), { status: 415 });

  await sweepEligibleUnreferencedBlobKeys(env, { did, limit: 20 }).catch((error) => {
    console.warn('[uploadBlob] Failed to sweep dereferenced blobs:', error);
  });

  let registeredCid: string | undefined;
  try {
    const identity = await blobIdentity(env, buf);

    const registration = await registerBlobRefWithQuota(
      env,
      did,
      identity.cid,
      identity.key,
      contentType,
      identity.size,
    );
    if (registration.tag === 'quotaExceeded') {
      return new Response(
        JSON.stringify({
          error: 'BlobQuotaExceeded',
          message: 'Blob storage quota exceeded',
        }),
        { status: 413, headers: { 'Content-Type': 'application/json' } },
      );
    }
    if (registration.tag === 'registered') registeredCid = identity.cid;

    await ensureBlobObject(env, registration.blob.key, buf, registration.blob.mime, registration.blob.size);

    // Mirror upstream shape exactly; helpful debugging header
    // Conform to lexicon: blob object must include $type: 'blob'
    const body = {
      blob: {
        $type: 'blob',
        ref: { $link: registration.blob.cid },
        mimeType: registration.blob.mime,
        size: registration.blob.size,
      },
    };
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    // Debug-only headers (safe for clients to ignore)
    headers['x-sniffed-mime'] = sniffed || '';
    headers['x-header-mime'] = headerMime;
    if (enc) headers['x-upload-encoding'] = enc;

    return new Response(JSON.stringify(body), { headers });
  } catch (error) {
    if (registeredCid) await deleteUnreferencedBlobRef(env, did, registeredCid).catch(() => undefined);
    if (String(errorMessage(error) || '').startsWith('BlobTooLarge')) return new Response(JSON.stringify({ error: 'PayloadTooLarge' }), { status: 413 });
    return new Response(JSON.stringify({ error: 'UploadFailed' }), { status: 500 });
  }
}

type BlobIdentity = {
  cid: string;
  key: string;
  size: number;
};

async function blobIdentity(env: Env, body: ArrayBuffer): Promise<BlobIdentity> {
  const size = body.byteLength;
  const limit = maxBlobBytes(env);
  if (size > limit) throw new Error(`BlobTooLarge:${size}>${limit}`);

  const digest = await sha256.digest(new Uint8Array(body));
  const cid = CID.createV1(0x55, digest);
  return {
    cid: cid.toString(),
    key: `blobs/by-cid/${base64Url(digest.digest)}`,
    size,
  };
}

async function ensureBlobObject(
  env: Env,
  key: string,
  body: ArrayBuffer,
  contentType: string,
  expectedSize: number,
): Promise<void> {
  const existing = await env.ALTERAN_BLOBS.head(key);
  if (existing?.size === expectedSize) return;
  await env.ALTERAN_BLOBS.put(key, body, { httpMetadata: { contentType } });
}

function maxBlobBytes(env: Env, defaultMax = 5 * 1024 * 1024): number {
  const raw = env.PDS_MAX_BLOB_SIZE;
  const parsed = raw ? Number(raw) : defaultMax;
  return Number.isFinite(parsed) && parsed > 0 ? parsed : defaultMax;
}

function base64Url(bytes: Uint8Array): string {
  let value = '';
  for (const byte of bytes) value += String.fromCharCode(byte);
  return btoa(value).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}
