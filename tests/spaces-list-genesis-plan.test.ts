import { expect } from '@std/expect';
import { DID } from './helpers/spaces-authorized-read';
import { EMPTY, policyFixture } from './helpers/spaces-policy-read';
import { genesisPrincipal } from './helpers/spaces-list-genesis';
import { listAuthorizedSpaceRecords } from '../src/db/space-authorized-list';

Deno.test('genesis witness follows authorization and uses indexed probes', async () => {
  const f = await policyFixture();
  const db = f.env.ALTERAN_DB;
  let sql = '';
  let values: unknown[] = [];
  const completions: Array<{ sql: string; values: unknown[] }> = [];
  const wrapped = new Proxy(db, { get(target, key) {
    if (key === 'prepare') return (query: string) => {
      const statement = target.prepare(query);
      const isPage = query.includes('candidates AS MATERIALIZED');
      const isCompletion = query.includes('space_personal_policy p') && query.includes('space_gc_attempt') &&
        (query.includes('RETURNING seconds, nonce') ||
          query.includes('SELECT clock.seconds, authorized.session_expires_at FROM authorized CROSS JOIN clock'));
      if (!isPage && !isCompletion) return statement;
      return new Proxy(statement, { get(inner, property) {
        if (property === 'bind') return (...args: unknown[]) => {
          if (isPage) { sql = query; values = args; }
          else completions.push({ sql: query, values: args });
          return inner.bind(...args);
        };
        const value = Reflect.get(inner, property, inner);
        return typeof value === 'function' ? value.bind(inner) : value;
      } });
    };
    const value = Reflect.get(target, key, target);
    return typeof value === 'function' ? value.bind(target) : value;
  } });
  const env = { ...f.env, ALTERAN_DB: wrapped };
  const current = await genesisPrincipal(f, env);
  const result = await listAuthorizedSpaceRecords(env, current.principal, current.request);
  expect(result.tag).toBe('found');
  if (result.tag !== 'found') throw new Error('Expected genesis page');
  const live = await db.prepare(sql).bind(...values).all<{ sentinel: number; genesis_nonce: string }>();
  expect(live.results).toHaveLength(1);
  expect(live.results[0].sentinel).toBe(1);
  expect(live.results[0].genesis_nonce).toMatch(/^[0-9a-f-]{36}$/);
  expect(await result.complete(current.request, env.ALTERAN_DB)).toBe(true);
  expect(completions).toHaveLength(2);
  for (const [index, statement] of completions.entries()) {
    const completionPlan = await db.prepare(`EXPLAIN QUERY PLAN ${statement.sql}`).bind(...statement.values)
      .all<{ detail: string }>();
    const details = completionPlan.results.map((row) => row.detail);
    const session = details.findIndex((line) => line.includes('SEARCH session USING INDEX sqlite_autoindex_oauth_session_1'));
    const authorized = index === 0 ? session : details.findIndex((line) => line === 'SCAN authorized');
    const history = details.findIndex((line) => line.includes('space_epoch_space_owner'));
    expect(session).toBeGreaterThanOrEqual(0);
    expect(authorized).toBeGreaterThanOrEqual(session);
    expect(history).toBeGreaterThan(authorized);
  }
  const liveSample = await db.prepare(completions[0].sql).bind(...completions[0].values).all<{ authorized: number }>();
  expect(liveSample.results[0].authorized).toBe(1);
  const liveFinal = await db.prepare(completions[1].sql).bind(...completions[1].values).all();
  expect(liveFinal.results).toHaveLength(1);
  if (!sql) throw new Error('Missing list selection');
  const plan = await db.prepare(`EXPLAIN QUERY PLAN ${sql}`).bind(...values).all<{ detail: string }>();
  const details = plan.results.map((row) => row.detail);
  const genesis = details.findIndex((line) => line.includes('MATERIALIZE genesis'));
  const authorized = details.findIndex((line, index) => index > genesis && line === 'SCAN authorized');
  const policy = details.findIndex((line, index) => index > genesis &&
    line.includes('SEARCH p USING INDEX sqlite_autoindex_space_personal_policy_1'));
  expect(genesis).toBeGreaterThanOrEqual(0);
  expect(authorized).toBeGreaterThan(genesis);
  expect(policy).toBeGreaterThan(authorized);
  for (const index of ['space_epoch_space_owner', 'space_record_version_space_owner_epoch',
    'space_snapshot_lease_owner_expiry', 'space_gc_attempt_owner', 'space_quarantine_job_owner_epoch',
    'space_mutation_attempt_owner', 'space_personal_deletion_attempt_owner']) {
    expect(details.findIndex((line, position) => position > authorized && line.includes(index))).toBeGreaterThan(authorized);
  }
  await db.prepare('UPDATE oauth_session SET revoked_at = unixepoch() WHERE id = ?').bind(f.sessionId).run();
  const revokedSample = await db.prepare(completions[0].sql).bind(...completions[0].values).all<{ authorized: number }>();
  expect(revokedSample.results[0].authorized).toBe(0);
  expect(Number(revokedSample.meta.rows_read)).toBeLessThan(Number(liveSample.meta.rows_read));
  const revokedFinal = await db.prepare(completions[1].sql).bind(...completions[1].values).all();
  expect(revokedFinal.results).toEqual([]);
  expect(Number(revokedFinal.meta.rows_read)).toBeLessThan(Number(liveFinal.meta.rows_read));
  const triggers = await db.prepare("SELECT name FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'space_epoch'")
    .all<{ name: string }>();
  for (const trigger of triggers.results) {
    await db.prepare(`DROP TRIGGER "${trigger.name.replaceAll('"', '""')}"`).run();
  }
  await db.prepare(`INSERT INTO space_epoch (id, space_ref, repo_did, state, created_at)
    VALUES ('history', ?, ?, 'retired', 0)`).bind(EMPTY, DID).run();
  const withHistorySample = await db.prepare(completions[0].sql).bind(...completions[0].values).all<{ authorized: number }>();
  const withHistoryFinal = await db.prepare(completions[1].sql).bind(...completions[1].values).all();
  expect(withHistorySample.results[0].authorized).toBe(0);
  expect(withHistoryFinal.results).toEqual([]);
  expect(withHistorySample.meta.rows_read).toBe(revokedSample.meta.rows_read);
  expect(withHistoryFinal.meta.rows_read).toBe(revokedFinal.meta.rows_read);
  await db.prepare('UPDATE oauth_replay_clock SET nonce = ? WHERE id = 1').bind(values[0]).run();
  const revoked = await db.prepare(sql).bind(...values).all();
  expect(revoked.results).toEqual([]);
  expect(Number(revoked.meta.rows_read)).toBeLessThan(Number(live.meta.rows_read));
});
