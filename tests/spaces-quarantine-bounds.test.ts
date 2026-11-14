import { expect } from '@std/expect';
import { Miniflare } from 'miniflare';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { encodeRecordBlock } from '../src/services/repo/blockstore-ops';
import { claimSpaceQuarantine, stepSpaceQuarantine } from './helpers/space-adapters';
import { bindQuarantineFixtureOwners } from './helpers/space-quarantine-owner';

Deno.test({ name: 'quarantine legacy metadata remains bounded when rejected', sanitizeOps: false, sanitizeResources: false, async fn() {
  const service = new Miniflare({ d1Databases: { DB: ':memory:' }, compatibilityDate: '2025-10-02',
    script: "export default { fetch: () => new Response('ok') }", modules: true });
  await service.ready;
  const database = await service.getD1Database('DB');
  const migrations = join(import.meta.dirname!, '..', 'migrations');
  const names = readdirSync(migrations).filter((name) => name.endsWith('.sql')).sort();
  const apply = async (name: string) => {
    for (const chunk of readFileSync(join(migrations, name), 'utf8').split('--> statement-breakpoint')) {
      if (chunk.trim()) await database.exec(chunk.trim().replace(/\n/g, ' '));
    }
  };
  for (const name of names.filter((name) => name < '0016')) await apply(name);
  const did = 'did:example:test';
  const space = `at://${did}/space/com.example.notes/a`;
  const rev = '3n2a5tw2wd22l';
  const [cid, value] = await encodeRecordBlock({ $type: 'com.example.note', text: 'test' });
  await database.prepare('INSERT INTO space (space_ref, authority_did, space_type, skey, created_at) VALUES (?, ?, ?, ?, 1)')
    .bind(space, did, 'com.example.notes', 'a').run();
  await database.prepare('INSERT INTO space_repo (space_ref, repo_did, rev, set_hash, generation, mutation_id) VALUES (?, ?, ?, ?, 7, ?)')
    .bind(space, did, rev, new Uint8Array(2048), 'legacy-mutation').run();
  await database.prepare('INSERT INTO space_record (space_ref, repo_did, collection, rkey, cid, value_cbor, repo_rev) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .bind(space, did, 'com.example.note', `\0${'x'.repeat(400_000)}`, cid.toString(), value, rev).run();
  for (const name of names.filter((name) => name >= '0016')) await apply(name);
  await bindQuarantineFixtureOwners(database);
  const env = { ALTERAN_DB: database, PDS_DID: did } as any;
  const handle = await claimSpaceQuarantine(env, space, did);
  if (!handle) throw new Error('Missing quarantine handle');
  let max = 0;
  const wrapped = new Proxy(database, { get(target, property) {
    if (property === 'batch') return async (statements: any[]) => {
      const result = await target.batch(statements);
      max = Math.max(max, JSON.stringify(result).length);
      return result;
    };
    const result = Reflect.get(target, property, target);
    return typeof result === 'function' ? result.bind(target) : result;
  } });
  expect((await stepSpaceQuarantine({ ...env, ALTERAN_DB: wrapped }, handle)).tag).toBe('invalid');
  expect(max).toBeLessThan(30_000);
  await service.dispose();
} });
