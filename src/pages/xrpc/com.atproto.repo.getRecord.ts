import type { APIContext } from 'astro';
import { getRecord as dalGetRecord } from '../../db/dal';
import {
  invalidRequest,
  optionalCid,
  requireLocalRepo,
  requireNsid,
  requireRecordKey,
  xrpcError,
} from '../../lib/local-xrpc';

export const prerender = false;

export async function GET({ locals, url }: APIContext) {
  const { env } = locals.runtime;
  if (url.searchParams.has('uri')) {
    return invalidRequest('uri is not a parameter for com.atproto.repo.getRecord');
  }

  const repo = requireLocalRepo(env, url, { notFoundError: 'RecordNotFound' });
  if (!repo.ok) return repo.response;

  const collection = requireNsid(url);
  if (!collection.ok) return collection.response;

  const rkey = requireRecordKey(url);
  if (!rkey.ok) return rkey.response;

  const requestedCid = optionalCid(url);
  if (!requestedCid.ok) return requestedCid.response;

  const uri = `at://${repo.value}/${collection.value}/${rkey.value}`;
  const row = await dalGetRecord(env, uri);
  if (!row) return xrpcError('RecordNotFound', 'Record not found');
  if (requestedCid.value && requestedCid.value.toString() !== row.cid) {
    return xrpcError('RecordNotFound', 'Record not found at requested CID');
  }

  return new Response(JSON.stringify({ uri: row.uri, cid: row.cid, value: JSON.parse(row.json) }), {
    headers: { 'Content-Type': 'application/json' },
  });
}
