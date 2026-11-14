import { expect } from '@std/expect';
import type { D1PreparedStatement } from '@cloudflare/workers-types';
import { describe, it } from './helpers/bdd';
import { claimSpaceQuarantine, stepSpaceQuarantine } from './helpers/space-adapters';
import { activateSpaceQuarantine } from '../src/db/space-quarantine-activation';
import { did, space, setup } from './helpers/space-quarantine-fixture';
import { COMPLETE_QUARANTINE_RESULT, QUARANTINE_CURRENT_PAGE, QUARANTINE_VERSION_PAGE } from '../src/db/space-quarantine-sql';

describe('quarantined space verification paging', () => {
  it('seeks directly to a late current-record cursor', async () => {
    const { env, database, dispose } = await setup([{ collection: 'com.example.note', rkey: 'a', text: 'a' }]);
    try {
      const handle = (await claimSpaceQuarantine(env, space, did))!;
      await database.prepare('DROP TRIGGER space_record_fence_insert').run();
      await database.prepare(`WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i + 1 FROM n WHERE i < 600)
        INSERT INTO space_record (space_ref, repo_did, collection, rkey, cid, value_cbor, repo_rev)
        SELECT r.space_ref, r.repo_did, r.collection, printf('k%04d', n.i), r.cid, r.value_cbor, r.repo_rev
        FROM space_record r CROSS JOIN n WHERE r.rkey = 'a'`).run();
      const nonce = (await database.prepare('SELECT renewal_nonce FROM space_quarantine_job WHERE id = ?')
        .bind(handle.id).first<{ renewal_nonce: string }>())!.renewal_nonce;
      const cursor = 'com.example.note/k0590';
      await database.prepare('UPDATE space_quarantine_job SET cursor = ? WHERE id = ?').bind(cursor, handle.id).run();
      const result = await database.prepare(QUARANTINE_CURRENT_PAGE)
        .bind(handle.id, handle.token, nonce, space, did, handle.ownerIncarnation,
          cursor, 0, new Uint8Array(2048), 0, cursor)
        .all<{ path: string | null; sentinel: number }>();
      expect(result.results.find((row) => row.sentinel === 0)?.path).toBe('com.example.note/k0591');
      expect(result.meta.rows_read).toBeLessThan(50);
    } finally {
      await dispose();
    }
  });

  it('seeks directly to EOF while completing, reading back and activating a large repo', async () => {
    const { env, database, dispose } = await setup([{ collection: 'com.example.note', rkey: 'a', text: 'a' }]);
    try {
      const handle = (await claimSpaceQuarantine(env, space, did))!;
      await database.prepare('DROP TRIGGER space_record_fence_insert').run();
      await database.prepare(`WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i + 1 FROM n WHERE i < 600)
        INSERT INTO space_record (space_ref, repo_did, collection, rkey, cid, value_cbor, repo_rev)
        SELECT r.space_ref, r.repo_did, r.collection, printf('k%04d', n.i), r.cid, r.value_cbor, r.repo_rev
        FROM space_record r CROSS JOIN n WHERE r.rkey = 'a'`).run();
      const cursor = 'com.example.note/k0600';
      await database.prepare(`UPDATE space_quarantine_job SET cursor = ?, sequence = 1,
        record_count = 601, accumulated_hash = expected_hash WHERE id = ?`).bind(cursor, handle.id).run();
      const batches: number[][] = [];
      const wrapped = new Proxy(database, {
        get(target, property) {
          if (property === 'batch') return async (statements: D1PreparedStatement[]) => {
            const result = await target.batch(statements);
            batches.push(result.map((entry) => entry.meta.rows_read));
            return result;
          };
          const value = Reflect.get(target, property, target);
          return typeof value === 'function' ? value.bind(target) : value;
        },
      });
      expect(await stepSpaceQuarantine({ ...env, ALTERAN_DB: wrapped }, handle)).toEqual({ tag: 'complete', records: 601 });
      expect(Math.max(...batches.flat())).toBeLessThan(100);
      const readback = await database.prepare(COMPLETE_QUARANTINE_RESULT)
        .bind(handle.id, handle.token, space, did, handle.ownerIncarnation, cursor, cursor, cursor).all();
      expect(readback.results).toHaveLength(1);
      expect(readback.meta.rows_read).toBeLessThan(100);
      await database.prepare('DROP TRIGGER space_epoch_quarantine_guard').run();
      batches.length = 0;
      expect(await activateSpaceQuarantine({ ...env, ALTERAN_DB: wrapped }, handle)).toBe('active');
      expect(Math.max(...batches.flat())).toBeLessThan(100);
    } finally {
      await dispose();
    }
  });

  it('fences page reads when the job changes between renewal and selection', async () => {
    for (const change of ['snapshot', 'nonce'] as const) {
      const { env, database, dispose } = await setup([{ collection: 'com.example.note', rkey: 'a', text: 'a' }]);
      try {
        const handle = (await claimSpaceQuarantine(env, space, did))!;
        let changed = false;
        const wrapped = new Proxy(database, {
          get(target, property) {
            if (property === 'batch') return async (statements: D1PreparedStatement[]) => {
              const result = await target.batch(statements);
              if (statements.length === 5 && !changed) {
                changed = true;
                if (change === 'snapshot') {
                  await target.prepare("UPDATE space_quarantine_job SET cursor = ?, sequence = sequence + 1, record_count = 1 WHERE id = ?")
                    .bind('com.example.note/z', handle.id).run();
                } else {
                  await target.prepare('UPDATE space_quarantine_job SET renewal_nonce = ? WHERE id = ?')
                    .bind(crypto.randomUUID(), handle.id).run();
                }
              }
              return result;
            };
            const value = Reflect.get(target, property, target);
            return typeof value === 'function' ? value.bind(target) : value;
          },
        });
        expect(await stepSpaceQuarantine({ ...env, ALTERAN_DB: wrapped }, handle)).toEqual({ tag: 'unavailable' });
        expect(changed).toBe(true);
        expect((await database.prepare('SELECT status FROM space_quarantine_job WHERE id = ?')
          .bind(handle.id).first<{ status: string }>())?.status).toBe('running');
      } finally {
        await dispose();
      }
    }
  });

  it('retries safely after the selected page response is lost', async () => {
    const { env, database, dispose } = await setup([{ collection: 'com.example.note', rkey: 'a', text: 'a' }]);
    try {
      const handle = (await claimSpaceQuarantine(env, space, did))!;
      let lost = false;
      const wrapped = new Proxy(database, {
        get(target, property) {
          if (property === 'batch') return async (statements: D1PreparedStatement[]) => {
            const result = await target.batch(statements);
            if (statements.length === 2 && !lost) { lost = true; throw new Error('Page response lost'); }
            return result;
          };
          const value = Reflect.get(target, property, target);
          return typeof value === 'function' ? value.bind(target) : value;
        },
      });
      expect(await stepSpaceQuarantine({ ...env, ALTERAN_DB: wrapped }, handle)).toEqual({ tag: 'unavailable' });
      expect(lost).toBe(true);
      expect((await database.prepare('SELECT record_count FROM space_quarantine_job WHERE id = ?')
        .bind(handle.id).first<{ record_count: number }>())?.record_count).toBe(0);
      expect(await stepSpaceQuarantine(env, handle)).toEqual({ tag: 'progress', records: 1 });
      expect(await stepSpaceQuarantine(env, handle)).toEqual({ tag: 'complete', records: 1 });
    } finally {
      await dispose();
    }
  });

  it('bounds corrupt version and current metadata before D1 transfer', async () => {
    const { env, database, dispose } = await setup([{ collection: 'com.example.note', rkey: 'a', text: 'a' }]);
    try {
      const handle = (await claimSpaceQuarantine(env, space, did))!;
      const nonce = (await database.prepare('SELECT renewal_nonce FROM space_quarantine_job WHERE id = ?')
        .bind(handle.id).first<{ renewal_nonce: string }>())!.renewal_nonce;
      const args = [handle.id, handle.token, nonce, space, did, handle.ownerIncarnation,
        '', 0, new Uint8Array(2048), 0, ''] as const;
      await database.prepare('DROP TRIGGER space_version_fence_update').run();
      await database.prepare('DROP TRIGGER space_record_version_update_guard').run();
      await database.prepare('DROP TRIGGER space_record_fence_update').run();
      const big = `x\0${'x'.repeat(400_000)}`;
      for (const [table, column, query] of [
        ['space_record_version', 'cid', QUARANTINE_VERSION_PAGE],
        ['space_record_version', 'repo_rev', QUARANTINE_VERSION_PAGE],
        ['space_record_version', 'space_ref', QUARANTINE_VERSION_PAGE],
        ['space_record', 'cid', QUARANTINE_CURRENT_PAGE],
        ['space_record', 'repo_rev', QUARANTINE_CURRENT_PAGE],
        ['space_record', 'rkey', QUARANTINE_CURRENT_PAGE],
      ] as const) {
        const original = await database.prepare(`SELECT ${column} AS value FROM ${table} LIMIT 1`).first<{ value: string }>();
        await database.prepare(`UPDATE ${table} SET ${column} = ?`).bind(big).run();
        const result = await database.prepare(query).bind(...args).all<{ sentinel: number; valid: number }>();
        expect(result.results.filter((row) => row.sentinel === 1).length).toBe(1);
        expect(result.results.filter((row) => row.sentinel === 0 && row.valid === 0).length).toBe(1);
        expect(JSON.stringify(result.results).length).toBeLessThan(30_000);
        await database.prepare(`UPDATE ${table} SET ${column} = ?`).bind(original!.value).run();
      }
      await database.prepare('UPDATE space_record_version SET rkey = ?, path = ?')
        .bind(big, `com.example.note/${big}`).run();
      const invalid = await database.prepare(QUARANTINE_VERSION_PAGE).bind(...args).all<{ sentinel: number; valid: number; path: string | null }>();
      expect(invalid.results.find((row) => row.sentinel === 0)).toMatchObject({ valid: 0, path: null });
      expect(JSON.stringify(invalid.results).length).toBeLessThan(30_000);
      expect(await stepSpaceQuarantine(env, handle)).toEqual({ tag: 'invalid' });
    } finally {
      await dispose();
    }
  });

  it('rejects malformed job state and never transfers oversized job fields', async () => {
    const { env, database, dispose } = await setup([{ collection: 'com.example.note', rkey: 'a', text: 'a' }]);
    try {
      const handle = (await claimSpaceQuarantine(env, space, did))!;
      let largest = 0;
      const guarded = new Proxy(database, {
        get(target, property) {
          if (property === 'batch') return async (statements: D1PreparedStatement[]) => {
            const result = await target.batch(statements);
            largest = Math.max(largest, JSON.stringify(result).length);
            return result;
          };
          const value = Reflect.get(target, property, target);
          return typeof value === 'function' ? value.bind(target) : value;
        },
      });
      await database.prepare('UPDATE space_quarantine_job SET cursor = ? WHERE id = ?')
        .bind(`a\0${'x'.repeat(400_000)}`, handle.id).run();
      expect(await stepSpaceQuarantine({ ...env, ALTERAN_DB: guarded }, handle)).toEqual({ tag: 'unavailable' });
      expect(largest).toBeLessThan(30_000);
      await database.prepare('UPDATE space_quarantine_job SET cursor = ? WHERE id = ?').bind('bad\0path', handle.id).run();
      expect(await stepSpaceQuarantine(env, handle)).toEqual({ tag: 'invalid' });
      await database.prepare('UPDATE space_quarantine_job SET cursor = ?, accumulated_hash = ? WHERE id = ?')
        .bind('', 'x'.repeat(2048), handle.id).run();
      expect(await stepSpaceQuarantine(env, handle)).toEqual({ tag: 'unavailable' });
      await database.prepare('DROP TRIGGER space_quarantine_job_identity').run();
      await database.prepare('UPDATE space_quarantine_job SET id = ? WHERE id = ?')
        .bind(`a\0${'x'.repeat(400_000)}`, handle.id).run();
      expect(await claimSpaceQuarantine(env, space, did)).toBeNull();
    } finally {
      await dispose();
    }
  });

  it('refuses to copy oversized or mistyped legacy head metadata into a job', async () => {
    for (const [column, value] of [
      ['mutation_id', `x\0${'x'.repeat(400_000)}`],
      ['rev', `3n2a5tw2wd22l\0${'x'.repeat(400_000)}`],
      ['set_hash', 'x'.repeat(2048)],
    ] as const) {
      const { env, database, dispose } = await setup([], false, async (db) => {
        await db.prepare(`UPDATE space_repo SET ${column} = ? WHERE space_ref = ?`).bind(value, space).run();
      });
      try {
        expect(await claimSpaceQuarantine(env, space, did)).toBeNull();
        expect((await database.prepare('SELECT COUNT(*) AS count FROM space_quarantine_job').first<{ count: number }>())?.count).toBe(0);
      } finally {
        await dispose();
      }
    }
  });

  it('fails closed on historical versions, invalid record revisions and blob usage', async () => {
    const duplicate = await setup([{ collection: 'com.example.note', rkey: 'a', text: 'a' }]);
    try {
      await duplicate.database.prepare('DROP TRIGGER space_version_fence_insert').run();
      await duplicate.database.prepare('DROP TRIGGER space_record_version_insert_guard').run();
      await duplicate.database.prepare(
        `INSERT INTO space_record_version (epoch_id, space_ref, repo_did, path, collection, rkey,
         from_generation, until_generation, cid, value_cbor, value_size, repo_rev)
         SELECT epoch_id, space_ref, repo_did, path, collection, rkey, 1, 2, cid, value_cbor, value_size, repo_rev
         FROM space_record_version WHERE space_ref = ?`,
      ).bind(space).run();
      const handle = await claimSpaceQuarantine(duplicate.env, space, did);
      expect(await stepSpaceQuarantine(duplicate.env, handle!)).toEqual({ tag: 'invalid' });
    } finally {
      await duplicate.dispose();
    }
    const future = await setup([{ collection: 'com.example.note', rkey: 'a', text: 'a' }], false, async (database) => {
      await database.prepare('UPDATE space_record SET repo_rev = ? WHERE space_ref = ?').bind('3zzzzzzzzzzzz', space).run();
    });
    try {
      const handle = await claimSpaceQuarantine(future.env, space, did);
      expect(await stepSpaceQuarantine(future.env, handle!)).toEqual({ tag: 'invalid' });
    } finally {
      await future.dispose();
    }
    const blob = await setup([{ collection: 'com.example.note', rkey: 'a', text: 'a' }], false, async (database) => {
      await database.prepare(
        `INSERT INTO space_blob_usage (space_ref, repo_did, collection, rkey, cid, key)
         VALUES (?, ?, 'com.example.note', 'a', 'legacy-cid', 'legacy-key')`,
      ).bind(space, did).run();
    });
    try {
      const handle = await claimSpaceQuarantine(blob.env, space, did);
      expect(await stepSpaceQuarantine(blob.env, handle!)).toEqual({ tag: 'progress', records: 1 });
      expect(await stepSpaceQuarantine(blob.env, handle!)).toEqual({ tag: 'unsupported' });
    } finally {
      await blob.dispose();
    }
  });
});
