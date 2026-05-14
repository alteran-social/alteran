import type { Env } from '../../env';

type ListBlobCidsParams = {
  did: string;
  since?: string;
  cursor?: string;
  limit: number;
};

export async function listBlobCids(
  env: Env,
  { did, since, cursor, limit }: ListBlobCidsParams,
): Promise<{ cids: string[]; cursor?: string }> {
  const pageSize = limit + 1;
  const clauses = ['did = ?'];
  const values: Array<string | number> = [did];
  if (since) {
    clauses.push('repo_rev > ?');
    values.push(since);
  }
  if (cursor) {
    clauses.push('cid > ?');
    values.push(cursor);
  }
  values.push(pageSize);

  const result = await env.ALTERAN_DB.prepare(
    `SELECT DISTINCT cid
     FROM blob_usage
     WHERE ${clauses.join(' AND ')}
     ORDER BY cid
     LIMIT ?`,
  )
    .bind(...values)
    .all<{ cid: string }>();

  const rows = result.results ?? [];
  const page = rows.slice(0, limit).map((row) => row.cid);
  return {
    cids: page,
    ...(page.length > 0 ? { cursor: page[page.length - 1] } : {}),
  };
}
