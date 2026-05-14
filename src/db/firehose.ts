import type { Env } from '../env';

const SUBSCRIBE_REPOS_SEQUENCE = 'subscribeRepos';

export async function allocateFirehoseSeq(env: Env): Promise<number> {
  const row = await env.ALTERAN_DB
    .prepare(
      `INSERT INTO firehose_sequence (id, next_seq)
       VALUES (?, 2)
       ON CONFLICT(id) DO UPDATE SET next_seq = next_seq + 1
       RETURNING next_seq - 1 AS seq`,
    )
    .bind(SUBSCRIBE_REPOS_SEQUENCE)
    .first<{ seq: number }>();

  const seq = Number(row?.seq);
  if (!Number.isSafeInteger(seq) || seq < 1) {
    throw new Error('failed to allocate subscribeRepos sequence');
  }
  return seq;
}
