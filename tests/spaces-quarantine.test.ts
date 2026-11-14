import { expect } from '@std/expect';
import type { D1PreparedStatement } from '@cloudflare/workers-types';
import { describe, it } from './helpers/bdd';
import { claimSpaceQuarantine, stepSpaceQuarantine } from './helpers/space-adapters';
import { activateSpaceQuarantine } from '../src/db/space-quarantine-activation';
import { did, space, setup } from './helpers/space-quarantine-fixture';
import { encodeRecordBlock } from '../src/services/repo/blockstore-ops';
import { applySpaceSetHashChanges, spaceRecordHashElement } from '../src/lib/spaces/lthash';
import { acquireSpaceSnapshot } from './helpers/space-adapters';
import { getSpaceRecord } from './helpers/space-adapters';
import { QUARANTINE_CURRENT_PAGE } from '../src/db/space-quarantine-sql';
import { revision } from './helpers/space-quarantine-fixture';

describe('quarantined space verification', () => {
  it('verifies both frozen views one record at a time and stays quarantined', async () => {
    const { env, database, dispose } = await setup([
      { collection: 'com.example.note', rkey: 'b', text: 'b' },
      { collection: 'com.example.note.sub', rkey: 'a', text: 'nested' },
      { collection: 'com.example.note', rkey: 'a', text: 'a' },
    ]);
    try {
      const handle = await claimSpaceQuarantine(env, space, did);
      expect(handle).not.toBeNull();
      const job = await database.prepare('SELECT renewal_nonce FROM space_quarantine_job WHERE id = ?')
        .bind(handle!.id).first<{ renewal_nonce: string }>();
      const plan = await database.prepare(`EXPLAIN QUERY PLAN ${QUARANTINE_CURRENT_PAGE}`)
        .bind(handle!.id, handle!.token, job!.renewal_nonce, space, did, handle!.ownerIncarnation,
          '', 0, new Uint8Array(2048), 0, '').all();
      expect(JSON.stringify(plan.results)).toContain('space_record_path_idx');
      expect(JSON.stringify(plan.results)).toContain('<expr>>?');
      for (let index = 1; index <= 3; index++) {
        expect(await stepSpaceQuarantine(env, handle!)).toEqual({ tag: 'progress', records: index });
      }
      expect(await stepSpaceQuarantine(env, handle!)).toEqual({ tag: 'complete', records: 3 });
      const row = await database.prepare('SELECT status, record_count, cursor FROM space_quarantine_job WHERE id = ?')
        .bind(handle!.id).first();
      expect(row).toEqual({ status: 'complete', record_count: 3, cursor: 'com.example.note/b' });
      expect(await getSpaceRecord(env, space, did, 'com.example.note', 'a')).toBeNull();
      await expect(acquireSpaceSnapshot(env, space, did)).rejects.toThrow();
    } finally {
      await dispose();
    }
  });

  it('completes an empty repo and fails a mismatching full set hash', async () => {
    for (const [records, wrongHash, expected] of [
      [[], false, 'complete'],
      [[{ collection: 'com.example.note', rkey: 'a', text: 'a' }], true, 'invalid'],
    ] as const) {
      const { env, dispose } = await setup([...records], wrongHash);
      try {
        const handle = await claimSpaceQuarantine(env, space, did);
        expect(handle).not.toBeNull();
        if (records.length) expect((await stepSpaceQuarantine(env, handle!)).tag).toBe('progress');
        expect((await stepSpaceQuarantine(env, handle!)).tag).toBe(expected);
      } finally {
        await dispose();
      }
    }
  });

  it('keeps activation disabled in migrations and can reclaim a completed job', async () => {
    const { env, database, dispose } = await setup([{ collection: 'com.example.note', rkey: 'a', text: 'a' }]);
    try {
      const first = await claimSpaceQuarantine(env, space, did);
      expect(await stepSpaceQuarantine(env, first!)).toEqual({ tag: 'progress', records: 1 });
      expect(await stepSpaceQuarantine(env, first!)).toEqual({ tag: 'complete', records: 1 });
      expect(await activateSpaceQuarantine(env, first!)).toBe('unavailable');
      expect(await database.prepare('SELECT status FROM space_quarantine_job WHERE id = ?').bind(first!.id).first())
        .toEqual({ status: 'complete' });
      await database.prepare('UPDATE space_quarantine_job SET lease_until = unixepoch() - 1 WHERE id = ?').bind(first!.id).run();
      const second = await claimSpaceQuarantine(env, space, did);
      expect(second).not.toBeNull();
      expect(second!.token).not.toBe(first!.token);
      await database.prepare('DROP TRIGGER space_epoch_quarantine_guard').run();
      await expect(database.prepare("UPDATE space_epoch SET state = 'active' WHERE space_ref = ?").bind(space).run())
        .rejects.toThrow();
      expect(await activateSpaceQuarantine(env, first!)).toBe('unavailable');
      expect(await activateSpaceQuarantine(env, second!)).toBe('active');
      expect(await getSpaceRecord(env, space, did, 'com.example.note', 'a')).not.toBeNull();
      await expect(database.prepare('UPDATE space_repo SET mutation_id = ? WHERE space_ref = ?').bind('old-worker', space).run())
        .rejects.toThrow();
    } finally {
      await dispose();
    }
  });

  it('rolls back every skipped activation step', async () => {
    const cases = [
      `CREATE TRIGGER skip_activation BEFORE UPDATE OF status ON space_quarantine_job
       WHEN NEW.status = 'activating' BEGIN SELECT RAISE(IGNORE); END`,
      `CREATE TRIGGER skip_activation BEFORE UPDATE OF state ON space_epoch
       WHEN NEW.state = 'active' BEGIN SELECT RAISE(IGNORE); END`,
      `CREATE TRIGGER skip_activation BEFORE UPDATE OF status ON space_quarantine_job
       WHEN NEW.status = 'active' BEGIN SELECT RAISE(IGNORE); END`,
    ];
    for (const trigger of cases) {
      const { env, database, dispose } = await setup([]);
      try {
        const handle = await claimSpaceQuarantine(env, space, did);
        expect(await stepSpaceQuarantine(env, handle!)).toEqual({ tag: 'complete', records: 0 });
        await database.prepare('DROP TRIGGER space_epoch_quarantine_guard').run();
        await database.prepare(trigger).run();
        expect(await activateSpaceQuarantine(env, handle!)).toBe('unavailable');
        expect(await database.prepare('SELECT status, activation_nonce FROM space_quarantine_job WHERE id = ?')
          .bind(handle!.id).first()).toEqual({ status: 'complete', activation_nonce: null });
        expect(await database.prepare('SELECT state, verified_job_id FROM space_epoch WHERE space_ref = ?')
          .bind(space).first()).toEqual({ state: 'quarantined', verified_job_id: null });
      } finally {
        await dispose();
      }
    }
  });

  it('allows only one competing activation and recovers a lost batch response', async () => {
    for (const loseResponse of [false, true]) {
      const { env, database, dispose } = await setup([]);
      try {
        const handle = await claimSpaceQuarantine(env, space, did);
        expect(await stepSpaceQuarantine(env, handle!)).toEqual({ tag: 'complete', records: 0 });
        await database.prepare('DROP TRIGGER space_epoch_quarantine_guard').run();
        if (loseResponse) {
          const interrupted = new Proxy(database, {
            get(target, property) {
              if (property === 'batch') return async (statements: D1PreparedStatement[]) => {
                await target.batch(statements);
                throw new Error('response lost');
              };
              const value = Reflect.get(target, property, target);
              return typeof value === 'function' ? value.bind(target) : value;
            },
          });
          expect(await activateSpaceQuarantine({ ...env, ALTERAN_DB: interrupted }, handle!)).toBe('active');
        } else {
          const outcomes = await Promise.all([
            activateSpaceQuarantine(env, handle!), activateSpaceQuarantine(env, handle!),
          ]);
          expect(outcomes.sort()).toEqual(['active', 'unavailable']);
        }
        const job = await database.prepare('SELECT status, activation_nonce FROM space_quarantine_job WHERE id = ?')
          .bind(handle!.id).first<{ status: string; activation_nonce: string }>();
        const epoch = await database.prepare('SELECT state, verified_job_id, activation_nonce FROM space_epoch WHERE space_ref = ?')
          .bind(space).first();
        expect(job?.status).toBe('active');
        expect(epoch).toEqual({ state: 'active', verified_job_id: handle!.id, activation_nonce: job!.activation_nonce });
      } finally {
        await dispose();
      }
    }
  });

  it('refuses activation with unverified legacy operations', async () => {
    const { env, database, dispose } = await setup([], false, async (database) => {
      await database.prepare(`INSERT INTO space_op (space_ref, repo_did, rev, ordinal, collection, rkey)
        VALUES (?, ?, ?, 0, 'com.example.note', 'a')`).bind(space, did, revision).run();
    });
    try {
      const handle = await claimSpaceQuarantine(env, space, did);
      expect(await stepSpaceQuarantine(env, handle!)).toEqual({ tag: 'complete', records: 0 });
      await database.prepare('DROP TRIGGER space_epoch_quarantine_guard').run();
      expect(await activateSpaceQuarantine(env, handle!)).toBe('unavailable');
      expect(await database.prepare('SELECT state FROM space_epoch WHERE space_ref = ?').bind(space).first())
        .toEqual({ state: 'quarantined' });
    } finally {
      await dispose();
    }
  });

  it('refuses activation if blob usage appears after verification', async () => {
    const { env, database, dispose } = await setup([]);
    try {
      const handle = await claimSpaceQuarantine(env, space, did);
      expect(await stepSpaceQuarantine(env, handle!)).toEqual({ tag: 'complete', records: 0 });
      await database.prepare('DROP TRIGGER space_blob_usage_fence_insert').run();
      await database.prepare(`INSERT INTO space_blob_usage (space_ref, repo_did, collection, rkey, cid, key)
        VALUES (?, ?, 'com.example.note', 'a', 'legacy', 'legacy')`).bind(space, did).run();
      await database.prepare('DROP TRIGGER space_epoch_quarantine_guard').run();
      expect(await activateSpaceQuarantine(env, handle!)).toBe('unavailable');
      expect(await database.prepare('SELECT state FROM space_epoch WHERE space_ref = ?').bind(space).first())
        .toEqual({ state: 'quarantined' });
    } finally {
      await dispose();
    }
  });

  it('reclaims an expired job without accepting the stale owner', async () => {
    const { env, database, dispose } = await setup([
      { collection: 'com.example.note', rkey: 'a', text: 'a' },
      { collection: 'com.example.note', rkey: 'b', text: 'b' },
    ]);
    try {
      const first = await claimSpaceQuarantine(env, space, did);
      expect(first).not.toBeNull();
      expect(await claimSpaceQuarantine(env, space, did)).toBeNull();
      expect(await stepSpaceQuarantine(env, first!)).toEqual({ tag: 'progress', records: 1 });
      await database.prepare('UPDATE space_quarantine_job SET lease_until = unixepoch() - 1 WHERE id = ?').bind(first!.id).run();
      const second = await claimSpaceQuarantine(env, space, did);
      expect(second).not.toBeNull();
      expect(second!.id).toBe(first!.id);
      expect(second!.token).not.toBe(first!.token);
      expect(await stepSpaceQuarantine(env, first!)).toEqual({ tag: 'unavailable' });
      expect(await stepSpaceQuarantine(env, second!)).toEqual({ tag: 'progress', records: 2 });
      expect(await stepSpaceQuarantine(env, second!)).toEqual({ tag: 'complete', records: 2 });
    } finally {
      await dispose();
    }
  });

  it('returns no data when renewal or progress updates are silently skipped', async () => {
    const { env, database, dispose } = await setup([{ collection: 'com.example.note', rkey: 'a', text: 'a' }]);
    try {
      const handle = await claimSpaceQuarantine(env, space, did);
      await database.prepare(
        `CREATE TRIGGER skip_quarantine_renew BEFORE UPDATE OF renewal_nonce ON space_quarantine_job
         BEGIN SELECT RAISE(IGNORE); END`,
      ).run();
      let selected: unknown;
      const monitored = new Proxy(database, {
        get(target, property) {
          if (property === 'batch') return async (statements: D1PreparedStatement[]) => {
            const result = await target.batch(statements);
            selected = result.slice(1).map((item) => item.results);
            return result;
          };
          const value = Reflect.get(target, property, target);
          return typeof value === 'function' ? value.bind(target) : value;
        },
      });
      expect(await stepSpaceQuarantine({ ...env, ALTERAN_DB: monitored }, handle!)).toEqual({ tag: 'unavailable' });
      expect(selected).toBeUndefined();
      await database.prepare('DROP TRIGGER skip_quarantine_renew').run();
      await database.prepare(
        `CREATE TRIGGER skip_quarantine_progress BEFORE UPDATE OF record_count ON space_quarantine_job
         BEGIN SELECT RAISE(IGNORE); END`,
      ).run();
      expect(await stepSpaceQuarantine(env, handle!)).toEqual({ tag: 'unavailable' });
      expect(await database.prepare('SELECT cursor, record_count FROM space_quarantine_job WHERE id = ?')
        .bind(handle!.id).first()).toEqual({ cursor: '', record_count: 0 });
      await database.prepare('DROP TRIGGER skip_quarantine_progress').run();
      expect(await stepSpaceQuarantine(env, handle!)).toEqual({ tag: 'progress', records: 1 });
      await database.prepare(
        `CREATE TRIGGER skip_quarantine_finish BEFORE UPDATE OF status ON space_quarantine_job
         WHEN NEW.status = 'complete' BEGIN SELECT RAISE(IGNORE); END`,
      ).run();
      expect(await stepSpaceQuarantine(env, handle!)).toEqual({ tag: 'unavailable' });
      expect(await database.prepare('SELECT status FROM space_quarantine_job WHERE id = ?')
        .bind(handle!.id).first()).toEqual({ status: 'running' });
      await database.prepare('DROP TRIGGER skip_quarantine_finish').run();
      expect(await stepSpaceQuarantine(env, handle!)).toEqual({ tag: 'complete', records: 1 });
    } finally {
      await dispose();
    }
  });

  it('isolates owners and rejects a version with a mismatched owner', async () => {
    const otherDid = 'did:example:other';
    const otherSpace = `at://${otherDid}/space/com.example.notes/b`;
    const { env, database, dispose } = await setup(
      [{ collection: 'com.example.note', rkey: 'a', text: 'first' }], false,
      async (database) => {
        const [cid, value] = await encodeRecordBlock({ $type: 'com.example.note', text: 'second' });
        const hash = applySpaceSetHashChanges(null, [{
          action: 'add', element: spaceRecordHashElement('com.example.note', 'a', cid.toString()),
        }]);
        await database.batch([
          database.prepare('INSERT INTO space (space_ref, authority_did, space_type, skey, created_at) VALUES (?, ?, ?, ?, 1)')
            .bind(otherSpace, otherDid, 'com.example.notes', 'b'),
          database.prepare('INSERT INTO space_repo (space_ref, repo_did, rev, set_hash, generation, mutation_id) VALUES (?, ?, ?, ?, 9, ?)')
            .bind(otherSpace, otherDid, revision, hash, 'other-mutation'),
          database.prepare(`INSERT INTO space_record (space_ref, repo_did, collection, rkey, cid, value_cbor, repo_rev)
            VALUES (?, ?, 'com.example.note', 'a', ?, ?, ?)`)
            .bind(otherSpace, otherDid, cid.toString(), value, revision),
        ]);
      },
    );
    try {
      const otherEnv = { ...env, PDS_DID: otherDid };
      const [first, second] = await Promise.all([
        claimSpaceQuarantine(env, space, did),
        claimSpaceQuarantine(otherEnv, otherSpace, otherDid),
      ]);
      expect(first).not.toBeNull();
      expect(second).not.toBeNull();
      expect(await stepSpaceQuarantine(env, { ...first!, spaceRef: otherSpace })).toEqual({ tag: 'unavailable' });
      expect(await stepSpaceQuarantine(env, first!)).toEqual({ tag: 'progress', records: 1 });
      expect(await stepSpaceQuarantine(otherEnv, second!)).toEqual({ tag: 'progress', records: 1 });
      expect(await stepSpaceQuarantine(env, first!)).toEqual({ tag: 'complete', records: 1 });
      expect(await stepSpaceQuarantine(otherEnv, second!)).toEqual({ tag: 'complete', records: 1 });
    } finally {
      await dispose();
    }
    const mismatch = await setup([{ collection: 'com.example.note', rkey: 'a', text: 'a' }]);
    try {
      await mismatch.database.prepare('DROP TRIGGER space_version_fence_update').run();
      await mismatch.database.prepare('DROP TRIGGER space_record_version_update_guard').run();
      await mismatch.database.prepare('UPDATE space_record_version SET repo_did = ? WHERE space_ref = ?')
        .bind(otherDid, space).run();
      const handle = await claimSpaceQuarantine(mismatch.env, space, did);
      expect(await stepSpaceQuarantine(mismatch.env, handle!)).toEqual({ tag: 'invalid' });
    } finally {
      await mismatch.dispose();
    }
  });

  it('rolls back an altered checkpoint and fences a replaced renewal token', async () => {
    const { env, database, dispose } = await setup([{ collection: 'com.example.note', rkey: 'a', text: 'a' }]);
    try {
      const handle = await claimSpaceQuarantine(env, space, did);
      await database.prepare(
        `CREATE TRIGGER change_quarantine_progress AFTER UPDATE OF record_count ON space_quarantine_job
         BEGIN UPDATE space_quarantine_job SET cursor = 'wrong' WHERE id = NEW.id; END`,
      ).run();
      expect(await stepSpaceQuarantine(env, handle!)).toEqual({ tag: 'unavailable' });
      expect(await database.prepare('SELECT cursor, record_count FROM space_quarantine_job WHERE id = ?')
        .bind(handle!.id).first()).toEqual({ cursor: '', record_count: 0 });
      await database.prepare('DROP TRIGGER change_quarantine_progress').run();
      await database.prepare(
        `CREATE TRIGGER replace_quarantine_token AFTER UPDATE OF renewal_nonce ON space_quarantine_job
         BEGIN UPDATE space_quarantine_job SET token = 'replaced' WHERE id = NEW.id; END`,
      ).run();
      expect(await stepSpaceQuarantine(env, handle!)).toEqual({ tag: 'unavailable' });
      expect(await database.prepare('SELECT cursor, record_count FROM space_quarantine_job WHERE id = ?')
        .bind(handle!.id).first()).toEqual({ cursor: '', record_count: 0 });
    } finally {
      await dispose();
    }
  });

  it('rejects same-sized corrupt bytes and unmatched view rows', async () => {
    const alternate = (await encodeRecordBlock({ $type: 'com.example.note', text: 'b' }))[1];
    const corrupt = await setup([{ collection: 'com.example.note', rkey: 'a', text: 'a' }], false, async (database) => {
      await database.prepare('UPDATE space_record SET value_cbor = ? WHERE space_ref = ? AND repo_did = ?')
        .bind(alternate, space, did).run();
    });
    try {
      const handle = await claimSpaceQuarantine(corrupt.env, space, did);
      expect(await stepSpaceQuarantine(corrupt.env, handle!)).toEqual({ tag: 'invalid' });
    } finally {
      await corrupt.dispose();
    }
    const extra = await setup([{ collection: 'com.example.note', rkey: 'a', text: 'a' }]);
    try {
      await extra.database.prepare('DROP TRIGGER space_record_fence_insert').run();
      const [cid, bytes] = await encodeRecordBlock({ $type: 'com.example.note', text: 'b' });
      await extra.database.prepare(
        `INSERT INTO space_record (space_ref, repo_did, collection, rkey, cid, value_cbor, repo_rev)
         VALUES (?, ?, ?, 'b', ?, ?, ?)`,
      ).bind(space, did, 'com.example.note', cid.toString(), bytes, revision).run();
      const handle = await claimSpaceQuarantine(extra.env, space, did);
      expect(await stepSpaceQuarantine(extra.env, handle!)).toEqual({ tag: 'progress', records: 1 });
      expect(await stepSpaceQuarantine(extra.env, handle!)).toEqual({ tag: 'invalid' });
    } finally {
      await extra.dispose();
    }
  });

  it('blocks changes to the quarantined space, head and current records', async () => {
    const { database, dispose } = await setup([{ collection: 'com.example.note', rkey: 'a', text: 'a' }]);
    try {
      for (const statement of [
        database.prepare('UPDATE space SET deleted_at = 1 WHERE space_ref = ?').bind(space),
        database.prepare('DELETE FROM space WHERE space_ref = ?').bind(space),
        database.prepare(`INSERT OR REPLACE INTO space (space_ref, authority_did, space_type, skey, created_at)
          VALUES (?, ?, 'com.example.notes', 'a', 1)`).bind(space, did),
        database.prepare('UPDATE space_repo SET mutation_id = ? WHERE space_ref = ?').bind('other', space),
        database.prepare('UPDATE space_record SET cid = ? WHERE space_ref = ?').bind('other', space),
        database.prepare('DELETE FROM space_record_version WHERE space_ref = ?').bind(space),
      ]) await expect(statement.run()).rejects.toThrow();
    } finally {
      await dispose();
    }
  });

  it('does not checkpoint bytes if the lease expires after a page or before the CAS', async () => {
    for (const expireOnBatch of [1, 2]) {
      const { env, database, dispose } = await setup([{ collection: 'com.example.note', rkey: 'a', text: 'a' }]);
      try {
        const handle = await claimSpaceQuarantine(env, space, did);
        let batches = 0;
        const delayed = new Proxy(database, {
          get(target, property) {
            if (property === 'batch') return async (statements: D1PreparedStatement[]) => {
              batches++;
              if (batches === 2 && expireOnBatch === 2) {
                await target.prepare('UPDATE space_quarantine_job SET lease_until = unixepoch() - 1 WHERE id = ?')
                  .bind(handle!.id).run();
              }
              const result = await target.batch(statements);
              if (batches === 1 && expireOnBatch === 1) {
                await target.prepare('UPDATE space_quarantine_job SET lease_until = unixepoch() - 1 WHERE id = ?')
                  .bind(handle!.id).run();
              }
              return result;
            };
            const value = Reflect.get(target, property, target);
            return typeof value === 'function' ? value.bind(target) : value;
          },
        });
        expect(await stepSpaceQuarantine({ ...env, ALTERAN_DB: delayed }, handle!)).toEqual({ tag: 'unavailable' });
        expect(await database.prepare('SELECT cursor, record_count FROM space_quarantine_job WHERE id = ?')
          .bind(handle!.id).first()).toEqual({ cursor: '', record_count: 0 });
        const replacement = await claimSpaceQuarantine(env, space, did);
        expect(await stepSpaceQuarantine(env, replacement!)).toEqual({ tag: 'progress', records: 1 });
      } finally {
        await dispose();
      }
    }
  });

});
