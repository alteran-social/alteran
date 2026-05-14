import type { APIContext } from 'astro';
import { canImportRepo } from '../../lib/auth-scope';
import { verifyResourceRequestHybrid, dpopResourceUnauthorized, handleResourceAuthError, insufficientScopeResponse } from '../../lib/oauth/resource';
import { checkRate } from '../../lib/ratelimit';
import { resolveSecret } from '../../lib/secrets';
import { baseMime } from '../../lib/util';
import { jsonError } from '../../lib/repo-write-validation';
import { importRepoCar, RepoImportError } from '../../services/repo/import-repo';

export const prerender = false;

export async function POST({ locals, request }: APIContext) {
  const { env } = locals.runtime;
  let auth: NonNullable<Awaited<ReturnType<typeof verifyResourceRequestHybrid>>>;
  try {
    const verified = await verifyResourceRequestHybrid(env, request);
    if (!verified) return dpopResourceUnauthorized(env);
    auth = verified;
  } catch (error) {
    const handled = await handleResourceAuthError(env, error);
    if (handled) return handled;
    throw error;
  }

  const did = await resolveSecret(env.PDS_DID);
  if (!did) return jsonError('InvalidRequest', 'PDS_DID is not configured');
  if (auth.did !== did) {
    return jsonError('InvalidRequest', 'authenticated user does not own this repo');
  }
  if (!canImportRepo(auth.access)) {
    return insufficientScopeResponse();
  }

  const rateLimitResponse = await checkRate(env, request, 'writes', { key: auth.did });
  if (rateLimitResponse) return rateLimitResponse;

  if (baseMime(request.headers.get('content-type')) !== 'application/vnd.ipld.car') {
    return jsonError('InvalidRequest', 'Content-Type must be application/vnd.ipld.car');
  }

  const declaredLength = request.headers.get('content-length');
  if (declaredLength === null) {
    return jsonError('InvalidRequest', 'Content-Length header required');
  }
  const expectedLength = Number(declaredLength);
  if (!Number.isInteger(expectedLength) || expectedLength < 0) {
    return jsonError('InvalidRequest', 'Content-Length must be a non-negative integer');
  }

  const bytes = new Uint8Array(await request.arrayBuffer());
  if (bytes.byteLength !== expectedLength) {
    return jsonError('InvalidRequest', 'Content-Length does not match body size');
  }

  try {
    await importRepoCar(env, did, bytes);
    return new Response(null, { status: 200 });
  } catch (error) {
    if (error instanceof RepoImportError) {
      return jsonError(error.error, error.message, error.status);
    }
    console.error('importRepo error:', error);
    return jsonError('InternalServerError', 'Failed to import repo', 500);
  }
}
