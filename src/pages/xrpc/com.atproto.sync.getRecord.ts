import type { APIContext } from 'astro';
import { RepoManager } from '../../services/repo-manager';
import { buildRecordProofCar } from '../../services/car';

export const prerender = false;

/**
 * com.atproto.sync.getRecord
 * Get a single record as a CAR file
 */
export async function GET({ locals, url }: APIContext) {
  const { env } = locals;

  const did = url.searchParams.get('did') || (env.PDS_DID as string);
  const collection = url.searchParams.get('collection');
  const rkey = url.searchParams.get('rkey');

  if (!collection || !rkey) {
    return new Response(
      JSON.stringify({ error: 'InvalidRequest', message: 'collection and rkey required' }),
      { status: 400, headers: { 'Content-Type': 'application/json' } }
    );
  }

  try {
    const { bytes } = await buildRecordProofCar(env as any, did, collection, rkey);
    return new Response(bytes as any, {
      status: 200,
      headers: {
        'Content-Type': 'application/vnd.ipld.car; version=1',
        'Content-Disposition': 'inline; filename="record-proof.car"',
      },
    });
  } catch (error) {
    console.error('getRecord error:', error);
    return new Response(
      JSON.stringify({ error: 'InternalServerError', message: String(error) }),
      { status: 500, headers: { 'Content-Type': 'application/json' } }
    );
  }
}
