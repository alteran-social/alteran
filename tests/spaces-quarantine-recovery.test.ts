import { expect } from '@std/expect';
import type { D1Database, D1PreparedStatement } from '@cloudflare/workers-types';
import { Miniflare } from 'miniflare';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it } from './helpers/bdd';
import type { Env } from '../src/env';
import { activateSpaceQuarantine } from '../src/db/space-quarantine-activation';
import { claimSpaceQuarantine, stepSpaceQuarantine } from './helpers/space-adapters';
import { applySpaceWrites } from './helpers/space-adapters';
import { bindQuarantineFixtureOwners } from './helpers/space-quarantine-owner';

const DID = 'did:example:test';
const SPACE = `at://${DID}/space/com.example.notes/recovery`;
const MIGRATIONS = join(import.meta.dirname, '..', 'migrations');

async function setup(options: { wrongHash?: boolean; blobUsage?: boolean } = {}) {
  const miniflare = new Miniflare({
    d1Databases: { DB: ':memory:' }, compatibilityDate: '2025-10-02',
    script: "export default { fetch: () => new Response('ok') }", modules: true,
  });
  await miniflare.ready;
  const database = await miniflare.getD1Database('DB') as unknown as D1Database;
  const names = readdirSync(MIGRATIONS).filter((name) => name.endsWith('.sql')).sort();
  const apply = async (name: string) => {
    for (const chunk of readFileSync(join(MIGRATIONS, name), 'utf8').split('--> statement-breakpoint')) {
      const statement = chunk.trim();
      if (statement) await database.exec(statement.replace(/\n/g, ' '));
    }
  };
  for (const name of names.filter((name) => name < '0016')) await apply(name);
  const hash = new Uint8Array(2048);
  if (options.wrongHash) hash.fill(1);
  await database.batch([
    database.prepare('INSERT INTO space (space_ref, authority_did, space_type, skey, created_at) VALUES (?, ?, ?, ?, 1)')
      .bind(SPACE, DID, 'com.example.notes', 'recovery'),
    database.prepare('INSERT INTO space_repo (space_ref, repo_did, rev, set_hash, generation, mutation_id) VALUES (?, ?, ?, ?, 7, ?)')
      .bind(SPACE, DID, '3n2a5tw2wd22l', hash, 'legacy-mutation'),
  ]);
  for (const name of names.filter((name) => name >= '0016')) await apply(name);
  await bindQuarantineFixtureOwners(database);
  if (options.blobUsage) {
    await database.prepare('DROP TRIGGER space_blob_usage_fence_insert').run();
    await database.prepare(`INSERT INTO space_blob_usage (space_ref, repo_did, collection, rkey, cid, key)
      VALUES (?, ?, 'com.example.note', 'blob', 'legacy', 'legacy')`).bind(SPACE, DID).run();
  }
  return { env: { ALTERAN_DB: database, PDS_DID: DID } as unknown as Env, database, dispose: () => miniflare.dispose() };
}

function interruptBatch(database: D1Database, length: number, afterCommit: () => Promise<void> = async () => {}) {
  let matchingBatches = 0;
  return new Proxy(database, {
    get(target, property) {
      if (property === 'batch') return async (statements: D1PreparedStatement[]) => {
        const result = await target.batch(statements);
        if (statements.length === length && ++matchingBatches === (length === 2 ? 2 : 1)) {
          await afterCommit();
          throw new Error('Database response lost');
        }
        return result;
      };
      const value = Reflect.get(target, property, target);
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });
}

async function waitForExpiry(database: D1Database, expires: number) {
  for (let attempt = 0; attempt < 60; attempt++) {
    const row = await database.prepare('SELECT unixepoch() > ? AS expired').bind(expires).first<{ expired: number }>();
    if (row?.expired === 1) return;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error('Lease did not expire in the fixture');
}

describe('quarantine recovery', () => {
  it('recovers a committed activation after a later write and supports idempotent retry', async () => {
    const { env, database, dispose } = await setup();
    try {
      const handle = await claimSpaceQuarantine(env, SPACE, DID);
      if (!handle) throw new Error('Missing verification handle');
      expect(await stepSpaceQuarantine(env, handle)).toEqual({ tag: 'complete', records: 0 });
      await database.prepare('DROP TRIGGER space_epoch_quarantine_guard').run();
      const interrupted = interruptBatch(database, 4, async () => {
        await applySpaceWrites(env, SPACE, DID, [{
          action: 'create', collection: 'com.example.note', rkey: 'later',
          record: { $type: 'com.example.note', text: 'written after activation' },
        }]);
      });
      expect(await activateSpaceQuarantine({ ...env, ALTERAN_DB: interrupted }, handle)).toBe('active');
      expect(await activateSpaceQuarantine(env, handle)).toBe('active');
      expect(await activateSpaceQuarantine(env, { ...handle, token: crypto.randomUUID() })).toBe('unavailable');
      const operation = await database.prepare('SELECT COUNT(*) AS count FROM space_op WHERE space_ref = ?')
        .bind(SPACE).first<{ count: number }>();
      expect(operation?.count).toBe(1);
    } finally {
      await dispose();
    }
  });

  it('recovers a committed activation after its original lease expires', async () => {
    const { env, database, dispose } = await setup();
    try {
      const handle = await claimSpaceQuarantine(env, SPACE, DID);
      if (!handle) throw new Error('Missing verification handle');
      expect(await stepSpaceQuarantine(env, handle)).toEqual({ tag: 'complete', records: 0 });
      await database.prepare('UPDATE space_quarantine_job SET lease_until = unixepoch() + 3 WHERE id = ?')
        .bind(handle.id).run();
      const job = await database.prepare('SELECT lease_until FROM space_quarantine_job WHERE id = ?')
        .bind(handle.id).first<{ lease_until: number }>();
      if (!job) throw new Error('Missing job');
      await database.prepare('DROP TRIGGER space_epoch_quarantine_guard').run();
      const interrupted = interruptBatch(database, 4, () => waitForExpiry(database, job.lease_until));
      expect(await activateSpaceQuarantine({ ...env, ALTERAN_DB: interrupted }, handle)).toBe('active');
      expect(await activateSpaceQuarantine(env, handle)).toBe('active');
    } finally {
      await dispose();
    }
  });

  it('keeps successful activation receipts immutable and prevents replacement', async () => {
    const { env, database, dispose } = await setup();
    try {
      const handle = await claimSpaceQuarantine(env, SPACE, DID);
      if (!handle) throw new Error('Missing verification handle');
      expect(await stepSpaceQuarantine(env, handle)).toEqual({ tag: 'complete', records: 0 });
      await database.prepare('DROP TRIGGER space_epoch_quarantine_guard').run();
      expect(await activateSpaceQuarantine(env, handle)).toBe('active');
      for (const statement of [
        'UPDATE space_quarantine_job SET token = ? WHERE id = ?',
        'UPDATE space_quarantine_job SET sequence = 0 WHERE id = ?',
      ]) {
        const query = statement.includes('token =')
          ? database.prepare(statement).bind(crypto.randomUUID(), handle.id)
          : database.prepare(statement).bind(handle.id);
        await expect(query.run()).rejects.toThrow();
      }
      await expect(database.prepare('INSERT OR REPLACE INTO space_quarantine_job SELECT * FROM space_quarantine_job WHERE id = ?')
        .bind(handle.id).run()).rejects.toThrow();
      await expect(database.prepare(`INSERT OR REPLACE INTO space_quarantine_job
        (id, token, renewal_nonce, space_ref, repo_did, epoch_id, authority_did, space_type, skey, generation,
         mutation_id, rev, expected_hash, accumulated_hash, cursor, sequence, record_count, lease_until, status,
         activation_nonce, created_at, failure_reason)
        SELECT ?, token, renewal_nonce, space_ref, repo_did, epoch_id, authority_did, space_type, skey, generation,
         mutation_id, rev, expected_hash, accumulated_hash, cursor, sequence, record_count, lease_until, 'running',
         NULL, created_at, NULL FROM space_quarantine_job WHERE id = ?`).bind(crypto.randomUUID(), handle.id).run())
        .rejects.toThrow();
      expect(await activateSpaceQuarantine(env, handle)).toBe('active');
    } finally {
      await dispose();
    }
  });

  it('recovers a completed verification after response loss and lease reclaim', async () => {
    const { env, database, dispose } = await setup();
    try {
      const first = await claimSpaceQuarantine(env, SPACE, DID);
      if (!first) throw new Error('Missing verification handle');
      const interrupted = interruptBatch(database, 2);
      expect(await stepSpaceQuarantine({ ...env, ALTERAN_DB: interrupted }, first)).toEqual({ tag: 'complete', records: 0 });
      expect(await stepSpaceQuarantine(env, first)).toEqual({ tag: 'complete', records: 0 });
      await database.prepare('UPDATE space_quarantine_job SET lease_until = unixepoch() - 1 WHERE id = ?')
        .bind(first.id).run();
      expect(await stepSpaceQuarantine(env, first)).toEqual({ tag: 'unavailable' });
      const second = await claimSpaceQuarantine(env, SPACE, DID);
      if (!second) throw new Error('Missing reclaimed handle');
      expect(second.token).not.toBe(first.token);
      expect(await stepSpaceQuarantine(env, first)).toEqual({ tag: 'unavailable' });
      expect(await stepSpaceQuarantine(env, second)).toEqual({ tag: 'complete', records: 0 });
    } finally {
      await dispose();
    }
  });

  it('preserves invalid and unsupported verification failures after response loss', async () => {
    for (const [options, expected] of [
      [{ wrongHash: true }, 'invalid'],
      [{ blobUsage: true }, 'unsupported'],
    ] as const) {
      const { env, database, dispose } = await setup(options);
      try {
        const handle = await claimSpaceQuarantine(env, SPACE, DID);
        if (!handle) throw new Error('Missing verification handle');
        let expires: number | undefined;
        if (expected === 'invalid') {
          await database.prepare('UPDATE space_quarantine_job SET lease_until = unixepoch() + 3 WHERE id = ?')
            .bind(handle.id).run();
          expires = (await database.prepare('SELECT lease_until FROM space_quarantine_job WHERE id = ?')
            .bind(handle.id).first<{ lease_until: number }>())?.lease_until;
        }
        const interrupted = interruptBatch(database, 2);
        expect(await stepSpaceQuarantine({ ...env, ALTERAN_DB: interrupted }, handle)).toEqual({ tag: expected });
        if (expires !== undefined) await waitForExpiry(database, expires);
        expect(await stepSpaceQuarantine(env, handle)).toEqual({ tag: expected });
        expect(await stepSpaceQuarantine(env, { ...handle, token: crypto.randomUUID() })).toEqual({ tag: 'unavailable' });
        await expect(database.prepare('UPDATE space_quarantine_job SET failure_reason = ? WHERE id = ?')
          .bind('other', handle.id).run()).rejects.toThrow();
        await expect(database.prepare('INSERT OR REPLACE INTO space_quarantine_job SELECT * FROM space_quarantine_job WHERE id = ?')
          .bind(handle.id).run()).rejects.toThrow();
      } finally {
        await dispose();
      }
    }
  });

  it('bounds malformed nonce reads in completed and active recovery', async () => {
    const { env, database, dispose } = await setup();
    try {
      const handle = (await claimSpaceQuarantine(env, SPACE, DID))!;
      expect(await stepSpaceQuarantine(env, handle)).toEqual({ tag: 'complete', records: 0 });
      const original = (await database.prepare('SELECT renewal_nonce FROM space_quarantine_job WHERE id = ?')
        .bind(handle.id).first<{ renewal_nonce: string }>())!.renewal_nonce;
      const oversized = `${original}\0${'x'.repeat(400_000)}`;
      await database.prepare('UPDATE space_quarantine_job SET renewal_nonce = ? WHERE id = ?').bind(oversized, handle.id).run();
      let largest = 0;
      const wrap = (statement: D1PreparedStatement): D1PreparedStatement => new Proxy(statement, {
        get(target, property) {
          if (property === 'bind') return (...args: unknown[]) => wrap(target.bind(...args));
          if (property === 'first') return async (...args: unknown[]) => {
            const result = await (target.first as (...values: unknown[]) => Promise<unknown>)(...args);
            largest = Math.max(largest, JSON.stringify(result).length);
            return result;
          };
          const value = Reflect.get(target, property, target);
          return typeof value === 'function' ? value.bind(target) : value;
        },
      });
      const monitored = new Proxy(database, {
        get(target, property) {
          if (property === 'prepare') return (sql: string) => wrap(target.prepare(sql));
          const value = Reflect.get(target, property, target);
          return typeof value === 'function' ? value.bind(target) : value;
        },
      });
      expect(await activateSpaceQuarantine({ ...env, ALTERAN_DB: monitored }, handle)).toBe('unavailable');
      expect(largest).toBeLessThan(1_000);
      await database.prepare('UPDATE space_quarantine_job SET renewal_nonce = ? WHERE id = ?').bind(original, handle.id).run();
      await database.prepare('DROP TRIGGER space_epoch_quarantine_guard').run();
      expect(await activateSpaceQuarantine(env, handle)).toBe('active');
      await database.prepare('DROP TRIGGER space_quarantine_job_terminal_immutable').run();
      await database.prepare('DROP TRIGGER space_quarantine_job_activation_nonce').run();
      await database.prepare('DROP TRIGGER space_quarantine_owner_update').run();
      await database.prepare('DROP TRIGGER space_epoch_verification_metadata').run();
      await database.batch([
        database.prepare('UPDATE space_quarantine_job SET activation_nonce = ? WHERE id = ?').bind(oversized, handle.id),
        database.prepare('UPDATE space_epoch SET activation_nonce = ? WHERE space_ref = ?').bind(oversized, SPACE),
      ]);
      largest = 0;
      expect(await activateSpaceQuarantine({ ...env, ALTERAN_DB: monitored }, handle)).toBe('unavailable');
      expect(largest).toBeLessThan(1_000);
    } finally {
      await dispose();
    }
  });

  it('rejects forged terminal reasons and replacement of a running job', async () => {
    const { env, database, dispose } = await setup();
    try {
      const handle = await claimSpaceQuarantine(env, SPACE, DID);
      if (!handle) throw new Error('Missing verification handle');
      await expect(database.prepare("UPDATE space_quarantine_job SET status = 'failed' WHERE id = ?")
        .bind(handle.id).run()).rejects.toThrow();
      await expect(database.prepare("UPDATE space_quarantine_job SET status = 'failed', failure_reason = 'other' WHERE id = ?")
        .bind(handle.id).run()).rejects.toThrow();
      await expect(database.prepare('INSERT OR REPLACE INTO space_quarantine_job SELECT * FROM space_quarantine_job WHERE id = ?')
        .bind(handle.id).run()).rejects.toThrow();
      expect(await stepSpaceQuarantine(env, handle)).toEqual({ tag: 'complete', records: 0 });
    } finally {
      await dispose();
    }
  });
});
