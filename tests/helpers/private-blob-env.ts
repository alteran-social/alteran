import { Miniflare } from 'miniflare';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { D1Database, R2Bucket } from '@cloudflare/workers-types';

const directory = join(import.meta.dirname!, '..', '..', 'migrations');
const workers: Miniflare[] = [];

export type PrivateBlobTestEnv = {
  ALTERAN_DB: D1Database;
  ALTERAN_BLOBS: R2Bucket;
  PUBLIC_BLOBS: R2Bucket;
};

export async function applyPrivateBlobMigrations(database: D1Database, from = 0, through = 9999): Promise<void> {
  const files = readdirSync(directory).filter((name) => name.endsWith('.sql')).sort();
  for (const file of files) {
    const number = Number(file.slice(0, 4));
    if (number < from || number > through) continue;
    const statements = readFileSync(join(directory, file), 'utf8').split('--> statement-breakpoint')
      .map((chunk) => chunk.trim()).filter(Boolean).map((sql) => database.prepare(sql.replace(/\n/g, ' ')));
    if (statements.length) await database.batch(statements);
  }
}

export async function makePrivateBlobEnv(through = 9999): Promise<PrivateBlobTestEnv> {
  const worker = new Miniflare({ d1Databases: { DB: ':memory:' }, r2Buckets: ['PRIVATE', 'PUBLIC'],
    compatibilityDate: '2025-10-02', script: "export default { fetch: () => new Response('ok') }", modules: true });
  workers.push(worker);
  await worker.ready;
  const ALTERAN_DB = await worker.getD1Database('DB') as unknown as D1Database;
  const ALTERAN_BLOBS = await worker.getR2Bucket('PRIVATE') as unknown as R2Bucket;
  const PUBLIC_BLOBS = await worker.getR2Bucket('PUBLIC') as unknown as R2Bucket;
  await applyPrivateBlobMigrations(ALTERAN_DB, 0, through);
  return { ALTERAN_DB, ALTERAN_BLOBS, PUBLIC_BLOBS };
}

export async function disposePrivateBlobEnv(): Promise<void> {
  await Promise.all(workers.splice(0).map((worker) => worker.dispose()));
}
