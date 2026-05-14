import type { APIContext } from 'astro';
import type { Env } from '../../env';
import { PayloadTooLarge } from '../../lib/errors';
import {
  verifyResourceRequestHybrid,
  dpopResourceUnauthorized,
  handleResourceAuthError,
  insufficientScopeResponse,
  type ResourceAuthContext,
} from '../../lib/oauth/resource';
import { canUploadBlob } from '../../lib/auth-scope';
import { verifyServiceAuth, isServiceAuthToken } from '../../lib/service-auth';
import { checkRate } from '../../lib/ratelimit';
import { sniffMime, baseMime, readBodyBounded, readStreamBounded } from '../../lib/util';
import {
  deleteUnreferencedBlobRef,
  isAccountActive,
  registerBlobRefWithQuota,
  sweepEligibleUnreferencedBlobKeys,
} from '../../db/dal';
import { resolveSecret } from '../../lib/secrets';
import { CID } from 'multiformats/cid';
import { sha256 } from 'multiformats/hashes/sha2';
import { jsonError } from '../../lib/repo-write-error';

export const prerender = false;

const UPLOAD_BLOB_LXM = 'com.atproto.repo.uploadBlob';

type UploadAuth =
  | { tag: 'service' }
  | { tag: 'user'; auth: ResourceAuthContext };

export async function POST({ locals, request }: APIContext) {
  const { env } = locals.runtime;
  const did = await resolveSecret(env.PDS_DID);
  if (!did) {
    return jsonError('InternalServerError', 'PDS_DID is not configured', 500);
  }
  const uploadAuth = await authenticateUpload(env, request, did);
  if (uploadAuth instanceof Response) return uploadAuth;
  if (uploadAuth.tag === 'user' && uploadAuth.auth.did !== did) {
    return jsonError('InvalidRequest', 'authenticated user does not own this repo', 400);
  }

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

  const rateLimitResponse = await checkRate(env, request, 'blob', { key: did });
  if (rateLimitResponse) return rateLimitResponse;

  const encoding = uploadEncoding(request);
  if (!isSupportedUploadEncoding(encoding)) {
    return jsonError('InvalidRequest', `unsupported content-encoding: ${encoding}`, 400);
  }
  let bytes: Uint8Array;
  try {
    bytes = await readUploadBytes(request, maxBlobBytes(env), encoding);
  } catch (error) {
    if (error instanceof PayloadTooLarge) {
      return jsonError('PayloadTooLarge', 'blob exceeds maximum size', 413);
    }
    return jsonError('InvalidRequest', 'failed to read upload body', 400);
  }
  const buf = toArrayBuffer(bytes);
  const headerMime = baseMime(request.headers.get('content-type'));
  const sniffed = sniffMime(buf);
  const contentType = resolveUploadMime(headerMime, sniffed);
  if (uploadAuth.tag === 'user' && !canUploadBlob(uploadAuth.auth.access, contentType)) {
    return insufficientScopeResponse();
  }

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
    if (encoding) headers['x-upload-encoding'] = encoding;

    return new Response(JSON.stringify(body), { headers });
  } catch (error) {
    if (registeredCid) await deleteUnreferencedBlobRef(env, did, registeredCid).catch(() => undefined);
    if (error instanceof PayloadTooLarge) {
      return jsonError('PayloadTooLarge', 'blob exceeds maximum size', 413);
    }
    return new Response(JSON.stringify({ error: 'UploadFailed' }), { status: 500 });
  }
}

async function authenticateUpload(env: Env, request: Request, did: string): Promise<UploadAuth | Response> {
  const authHeader = request.headers.get('authorization');
  const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7).trim() : null;

  if (token && isServiceAuthToken(token)) {
    const serviceAuth = await verifyServiceAuth(env, request);
    if (!serviceAuth || serviceAuth.lxm !== UPLOAD_BLOB_LXM || serviceAuth.iss !== did) {
      return jsonError('InvalidToken', 'Invalid service auth token', 401);
    }
    return { tag: 'service' };
  }

  try {
    const auth = await verifyResourceRequestHybrid(env, request);
    if (!auth) return dpopResourceUnauthorized(env);
    return { tag: 'user', auth };
  } catch (error) {
    const handled = await handleResourceAuthError(env, error);
    if (handled) return handled;
    throw error;
  }
}

async function readUploadBytes(
  request: Request,
  maxBytes: number,
  encoding: string,
): Promise<Uint8Array> {
  if (!isCompressedEncoding(encoding)) {
    return readBodyBounded(request, maxBytes);
  }
  const decompressed = request.body?.pipeThrough(createDecompressionStream(encoding));
  return readStreamBounded(decompressed ?? null, maxBytes);
}

function uploadEncoding(request: Request): string {
  return (request.headers.get('content-encoding') || '').trim().toLowerCase();
}

function isCompressedEncoding(encoding: string): boolean {
  return encoding === 'gzip' || encoding === 'deflate' || encoding === 'deflate-raw';
}

function isSupportedUploadEncoding(encoding: string): boolean {
  return encoding === '' || isCompressedEncoding(encoding);
}

function resolveUploadMime(headerMime: string, sniffed: string | null): string {
  if (!sniffed) return headerMime;
  if (sniffed === 'video/webm' && (headerMime === 'audio/webm' || headerMime === 'video/webm')) {
    return headerMime;
  }
  if (sniffed === 'video/mp4' && (headerMime === 'audio/mp4' || headerMime === 'video/mp4')) {
    return headerMime;
  }
  return sniffed;
}

function createDecompressionStream(encoding: string): TransformStream<Uint8Array, Uint8Array> {
  const Decompression = globalThis.DecompressionStream as unknown as {
    new (format: string): TransformStream<Uint8Array, Uint8Array>;
  };
  return new Decompression(encoding);
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

type BlobIdentity = {
  cid: string;
  key: string;
  size: number;
};

async function blobIdentity(env: Env, body: ArrayBuffer): Promise<BlobIdentity> {
  const size = body.byteLength;
  const limit = maxBlobBytes(env);
  if (size > limit) throw new PayloadTooLarge('blob exceeds maximum size');

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
