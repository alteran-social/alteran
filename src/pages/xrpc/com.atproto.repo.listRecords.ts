import type { APIContext } from 'astro';
import { RepoManager } from '../../services/repo-manager';

export const prerender = false;

/**
 * com.atproto.repo.listRecords
 * List records in a collection with pagination
 */
export async function GET({ locals, url }: APIContext) {
  const { env } = locals;

  const repo = url.searchParams.get('repo') || (env.PDS_DID as string);
  const collection = url.searchParams.get('collection');
  const limit = parseInt(url.searchParams.get('limit') || '50', 10);
  const cursor = url.searchParams.get('cursor') || undefined;

  if (!collection) {
    return new Response(
      JSON.stringify({ error: 'InvalidRequest', message: 'collection parameter required' }),
      { status: 400, headers: { 'Content-Type': 'application/json' } }
    );
  }

  try {
    const repoManager = new RepoManager(env);
    const results = await repoManager.listRecords(collection, limit, cursor);

    const records = await Promise.all(
      results.map(async ({ key, cid }) => {
        const record = await repoManager.getRecord(collection, key);
        return {
          uri: `at://${repo}/${collection}/${key}`,
          cid: cid.toString(),
          value: record,
        };
      })
    );

    return new Response(
      JSON.stringify({
        records,
        cursor: records.length > 0 ? results[results.length - 1].key : undefined,
      }),
      {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }
    );
  } catch (error) {
    console.error('listRecords error:', error);
    return new Response(
      JSON.stringify({ error: 'InternalServerError', message: String(error) }),
      { status: 500, headers: { 'Content-Type': 'application/json' } }
    );
  }
}
