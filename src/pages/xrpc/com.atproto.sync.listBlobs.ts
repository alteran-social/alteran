import type { APIContext } from 'astro';
import { ensureValidDid, isValidTid } from '@atproto/syntax';
import { isAccountActive } from '../../db/dal';
import { listBlobCids } from '../../services/repo/list-blobs';
import { resolveSecret } from '../../lib/secrets';

export const prerender = false;

/**
 * com.atproto.sync.listBlobs
 * List blob CIDs for a DID
 */
export async function GET({ locals, url }: APIContext) {
  const { env } = locals;

  const configuredDid = await resolveSecret(env.PDS_DID);
  const did = url.searchParams.get('did') ?? undefined;
  const since = url.searchParams.get('since') ?? undefined;
  const cursor = url.searchParams.get('cursor') ?? undefined;
  const limit = parseLimit(url.searchParams.get('limit'));
  if (!did) return jsonError('InvalidRequest', 'did is required');
  if (!isValidDid(did)) return jsonError('InvalidRequest', 'did must be valid');
  if (!limit) return jsonError('InvalidRequest', 'limit must be an integer between 1 and 1000');
  if (since && !isValidTid(since)) return jsonError('InvalidRequest', 'since must be a valid TID');
  if (!configuredDid || did !== configuredDid) return jsonError('RepoNotFound', 'Repo not found');

  try {
    const active = await isAccountActive(env, did);
    if (!active) {
      return jsonError('RepoDeactivated', 'Repo is deactivated');
    }

    const blobs = await listBlobCids(env, { did, since, cursor, limit });

    return new Response(
      JSON.stringify({
        cids: blobs.cids,
        ...(blobs.cursor ? { cursor: blobs.cursor } : {}),
      }),
      {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }
    );
  } catch (error) {
    console.error('listBlobs error:', error);
    return new Response(
      JSON.stringify({ error: 'InternalServerError', message: String(error) }),
      { status: 500, headers: { 'Content-Type': 'application/json' } }
    );
  }
}

function parseLimit(value: string | null): number | null {
  if (value === null || value === '') return 500;
  if (!/^\d+$/.test(value)) return null;
  const limit = Number(value);
  return Number.isInteger(limit) && limit >= 1 && limit <= 1000 ? limit : null;
}

function jsonError(error: string, message: string): Response {
  return new Response(
    JSON.stringify({ error, message }),
    { status: 400, headers: { 'Content-Type': 'application/json' } },
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
