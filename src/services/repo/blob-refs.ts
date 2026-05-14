import type { Env } from '../../env';
import { RepoWriteError } from '../../lib/repo-write-error';
import { collectBlobRefs } from '../../lib/repo-write-data';

export async function assertBlobKeysAvailable(env: Env, did: string, keys: string[]): Promise<void> {
  for (const key of new Set(keys)) {
    const row = await env.ALTERAN_DB.prepare(
      'SELECT cid, size FROM blob WHERE did = ? AND key = ? LIMIT 1',
    )
      .bind(did, key)
      .first<{ cid: string; size: number }>();
    if (!row) {
      throw new RepoWriteError('BlobNotFound', 'blob not found');
    }
    const object = await env.ALTERAN_BLOBS.head(key);
    if (!object || object.size !== Number(row.size)) {
      throw new RepoWriteError('BlobNotFound', `blob not found: ${row.cid}`);
    }
  }
}

export async function resolveRecordBlobKeys(env: Env, did: string, record: unknown): Promise<string[]> {
  const refs: Array<{ cid: string; mimeType: string; size: number }> = [];
  collectBlobRefs(record, refs);
  const keys = new Set<string>();
  for (const ref of refs) {
    const row = await env.ALTERAN_DB.prepare(
      'SELECT key, mime, size FROM blob WHERE did = ? AND cid = ? LIMIT 1',
    )
      .bind(did, ref.cid)
      .first<{ key: string; mime: string; size: number }>();
    if (!row) {
      throw new RepoWriteError('BlobNotFound', `blob not found: ${ref.cid}`);
    }
    if (row.mime !== ref.mimeType) {
      throw new RepoWriteError('InvalidMimeType', `blob mime type mismatch: ${ref.cid}`);
    }
    if (Number(row.size) !== ref.size) {
      throw new RepoWriteError('InvalidSize', `blob size mismatch: ${ref.cid}`);
    }
    const object = await env.ALTERAN_BLOBS.head(row.key);
    if (!object || object.size !== Number(row.size)) {
      throw new RepoWriteError('BlobNotFound', `blob not found: ${ref.cid}`);
    }
    keys.add(row.key);
  }
  return Array.from(keys);
}
