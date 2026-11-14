import { expect } from '@std/expect';
import { describe, it } from './helpers/bdd';
import { interceptRead } from './helpers/spaces-authorized-read';
import { EMPTY, policyFixture } from './helpers/spaces-policy-read';
import { listContext, signedGenesisRequest, type GenesisFixture } from './helpers/spaces-list-genesis';
import { GET } from '../src/pages/xrpc/com.atproto.space.listRecords';

type Environment = GenesisFixture['env'];
type Fault = 'prepare' | 'bind' | 'batch' | 'sample' | 'final' | 'missing' | 'sentinel' | 'budget' |
  'witness' | 'final-witness' | 'epoch' | 'extra-row';

function faulty(env: Environment, fault: Fault): Environment {
  const database = env.ALTERAN_DB;
  const wrapped = new Proxy(database, { get(target, key) {
    if (key === 'batch') return async (statements: Parameters<typeof database.batch>[0]) => {
      if (statements.length !== 6) return database.batch(statements);
      if (fault === 'batch') throw new Error('private batch failure');
      const result = await database.batch(statements);
      if (fault === 'missing') (result[2] as { results?: unknown }).results = null;
      else {
        const rows = result[2].results as Record<string, unknown>[];
        const sentinel = rows.find((row) => row.sentinel === 1);
        if (!sentinel) throw new Error('Missing sentinel');
        if (fault === 'sentinel') sentinel.sentinel = 0;
        if (fault === 'budget') sentinel.budget_total = 1;
        if (fault === 'witness') sentinel.genesis_nonce = crypto.randomUUID();
        if (fault === 'epoch') sentinel.epoch_id = 'fake-epoch';
        if (fault === 'extra-row') rows.push({ ...sentinel, sentinel: 0 });
      }
      if (fault === 'final-witness') (result[5].results as Record<string, unknown>[])[0].genesis_nonce = crypto.randomUUID();
      return result;
    };
    if (key === 'prepare') return (sql: string) => {
      const selection = sql.includes('candidates AS MATERIALIZED');
      const genesis = sql.includes('space_personal_policy p') && sql.includes('space_gc_attempt');
      const sample = genesis && sql.includes('RETURNING seconds, nonce');
      const final = genesis && sql.includes('SELECT clock.seconds, authorized.session_expires_at FROM authorized CROSS JOIN clock');
      if (selection && fault === 'prepare') throw new Error('private prepare failure');
      const statement = database.prepare(sql);
      if (!(selection && fault === 'bind') && !(sample && fault === 'sample') && !(final && fault === 'final')) return statement;
      return new Proxy(statement, { get(prepared, property) {
        if (property === 'bind') return (...values: Parameters<typeof prepared.bind>) => {
          if (selection && fault === 'bind') throw new Error('private bind failure');
          const bound = prepared.bind(...values);
          return new Proxy(bound, { get(boundTarget, member) {
            if (member === 'first') return async () => { throw new Error('private completion failure'); };
            const value = Reflect.get(boundTarget, member, boundTarget);
            return typeof value === 'function' ? value.bind(boundTarget) : value;
          } });
        };
        const value = Reflect.get(prepared, property, prepared);
        return typeof value === 'function' ? value.bind(prepared) : value;
      } });
    };
    const value = Reflect.get(target, key, target);
    return typeof value === 'function' ? value.bind(target) : value;
  } });
  return { ...env, ALTERAN_DB: wrapped };
}

describe('fresh personal Space list faults', () => {
  it('denies database faults and malformed witnesses without details', async () => {
    for (const fault of ['prepare', 'bind', 'batch', 'sample', 'final', 'missing', 'sentinel', 'budget',
      'witness', 'final-witness', 'epoch', 'extra-row'] as const) {
      const f = await policyFixture();
      const env = faulty(f.env, fault);
      const request = await signedGenesisRequest(f, { env });
      const response = await GET(listContext(env, request));
      expect(response.status).toBe(401);
      expect(await response.text()).not.toContain('private');
      expect(response.headers.get('cache-control')).toBe('private, no-store');
    }
  });

  it('does not project corrupt or oversized policy metadata', async () => {
    const f = await policyFixture();
    await f.env.ALTERAN_DB.prepare('DROP TRIGGER space_personal_policy_update').run();
    const original = await f.env.ALTERAN_DB.prepare('SELECT creation_nonce, created_at, authority_did, authority_incarnation FROM space_personal_policy WHERE space_ref = ?')
      .bind(EMPTY).first<Record<string, string | number>>();
    if (!original) throw new Error('Missing fixture policy');
    for (const [field, value] of [
      ['creation_nonce', 'invalid-nonce'], ['creation_nonce', 'x'.repeat(36)],
      ['creation_nonce', `x\u0000${'y'.repeat(34)}`], ['creation_nonce', `x\u0000${'y'.repeat(400_000)}`],
      ['created_at', 'invalid'], ['authority_did', 'did:example:other'], ['authority_incarnation', '0'.repeat(32)],
    ] as const) {
      await f.env.ALTERAN_DB.prepare(`UPDATE space_personal_policy SET ${field} = ? WHERE space_ref = ?`).bind(value, EMPTY).run();
      const watched = interceptRead(f.env);
      const request = await signedGenesisRequest(f, { env: watched.env });
      watched.arm();
      const response = await GET(listContext(watched.env, request));
      expect(response.status).toBe(401);
      expect(JSON.stringify(watched.returned()).length).toBeLessThan(1_000);
      await f.env.ALTERAN_DB.prepare(`UPDATE space_personal_policy SET ${field} = ? WHERE space_ref = ?`)
        .bind(original[field], EMPTY).run();
    }
    await f.env.ALTERAN_DB.prepare('UPDATE space_personal_policy SET created_at = ? WHERE space_ref = ?')
      .bind(Number(original.created_at) + 1, EMPTY).run();
    const mismatch = await signedGenesisRequest(f);
    expect((await GET(listContext(f.env, mismatch))).status).toBe(401);
  });
});
