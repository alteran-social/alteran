import { expect } from '@std/expect';
import { describe, it } from './helpers/bdd';
import { interceptRead } from './helpers/spaces-authorized-read';
import { EMPTY, MISSING, policyContext, policyFixture, signedPolicyRequest } from './helpers/spaces-policy-read';
import { createPersonalSpace } from '../src/db/space-lifecycle-create';
import { GET } from '../src/pages/xrpc/com.atproto.space.getSpace';

type Fixture = Awaited<ReturnType<typeof policyFixture>>;
type Environment = Fixture['env'];
type Fault = 'prepare' | 'bind' | 'batch' | 'sample' | 'final' | 'malformed' | 'sentinel' | 'identity';

function faulty(env: Environment, fault: Fault): Environment {
  const database = env.ALTERAN_DB;
  const wrapped = new Proxy(database, { get(target, key) {
    if (key === 'batch') return async (statements: Parameters<typeof database.batch>[0]) => {
      if (statements.length !== 6) return database.batch(statements);
      if (fault === 'batch') throw new Error('private batch failure');
      const result = await database.batch(statements);
      if (fault === 'malformed') (result[2] as { results?: unknown }).results = null;
      if (fault === 'sentinel') {
        const rows = result[2].results as { sentinel: number }[];
        rows.find((row) => row.sentinel === 1)!.sentinel = 0;
      }
      if (fault === 'identity') {
        const final = result[5].results as { creation_nonce: unknown }[];
        final[0].creation_nonce = crypto.randomUUID();
      }
      return result;
    };
    if (key === 'prepare') return (sql: string) => {
      const candidate = sql.includes('candidate AS MATERIALIZED');
      const sample = sql.includes('RETURNING seconds, nonce');
      const final = sql.includes('SELECT clock.seconds, authorized.session_expires_at FROM clock JOIN authorized');
      if (candidate && fault === 'prepare') throw new Error('private prepare failure');
      const statement = database.prepare(sql);
      if (!(candidate && fault === 'bind') && !(sample && fault === 'sample') && !(final && fault === 'final')) return statement;
      return new Proxy(statement, { get(prepared, property) {
        if (property === 'bind') return (...values: Parameters<typeof prepared.bind>) => {
          if (candidate && fault === 'bind') throw new Error('private bind failure');
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

function interceptCompletion(env: Environment, after: 'sample' | 'final', action: (watched: Environment) => Promise<void>) {
  const database = env.ALTERAN_DB;
  const watched = { ...env };
  let called = false;
  const wrapped = new Proxy(database, { get(target, key) {
    if (key === 'prepare') return (sql: string) => {
      const statement = database.prepare(sql);
      const sample = sql.includes('RETURNING seconds, nonce');
      const final = sql.includes('SELECT clock.seconds, authorized.session_expires_at FROM clock JOIN authorized');
      if ((after === 'sample' && !sample) || (after === 'final' && !final)) return statement;
      return new Proxy(statement, { get(prepared, property) {
        if (property === 'bind') return (...values: Parameters<typeof prepared.bind>) => {
          const bound = prepared.bind(...values);
          return new Proxy(bound, { get(boundTarget, member) {
            if (member === 'first') return async () => {
              const row = await bound.first();
              called = true;
              await action(watched);
              return row;
            };
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
  watched.ALTERAN_DB = wrapped;
  return { env: watched, called: () => called };
}

describe('Space policy read fault boundaries', () => {
  it('denies prepare, bind, batch, malformed and completion faults without detail', async () => {
    for (const fault of ['prepare', 'bind', 'batch', 'sample', 'final', 'malformed', 'sentinel', 'identity'] as const) {
      const f = await policyFixture();
      const env = faulty(f.env, fault);
      const response = await GET(policyContext(env, await signedPolicyRequest(f, EMPTY, { env })));
      expect(response.status).toBe(401);
      expect(await response.text()).not.toContain('private');
      expect(response.headers.get('cache-control')).toBe('private, no-store');
    }
  });

  it('rejects oversized and embedded-NUL policy metadata without transferring it', async () => {
    const f = await policyFixture();
    await f.env.ALTERAN_DB.prepare('DROP TRIGGER space_personal_policy_update').run();
    const saved = await f.env.ALTERAN_DB.prepare('SELECT creation_nonce, created_at FROM space_personal_policy WHERE space_ref = ?')
      .bind(EMPTY).first<{ creation_nonce: string; created_at: number }>();
    if (!saved) throw new Error('Missing policy');
    const large = `x\u0000${'y'.repeat(400_000)}`;
    for (const field of ['creation_nonce', 'created_at']) {
      await f.env.ALTERAN_DB.prepare(`UPDATE space_personal_policy SET ${field} = ? WHERE space_ref = ?`).bind(large, EMPTY).run();
      const watched = interceptRead(f.env);
      const request = await signedPolicyRequest(f, EMPTY, { env: watched.env });
      watched.arm();
      const response = await GET(policyContext(watched.env, request));
      expect(response.status).toBe(401);
      expect(JSON.stringify(watched.returned()).length).toBeLessThan(1_000);
      await f.env.ALTERAN_DB.prepare(`UPDATE space_personal_policy SET ${field} = ? WHERE space_ref = ?`)
        .bind(saved[field], EMPTY).run();
    }
  });

  it('rechecks authorization and absence after the completion sample', async () => {
    for (const mode of ['found-revoked', 'missing-revoked', 'missing-created', 'final-database'] as const) {
      const f = await policyFixture();
      const target = mode.startsWith('missing') ? MISSING : EMPTY;
      const watched = interceptCompletion(f.env, mode === 'final-database' ? 'final' : 'sample', async (env) => {
        if (mode.endsWith('revoked')) await f.env.ALTERAN_DB.prepare('UPDATE oauth_session SET revoked_at = unixepoch() WHERE id = ?')
          .bind(f.sessionId).run();
        if (mode === 'missing-created') await createPersonalSpace(f.env, MISSING,
          { $type: 'com.atproto.personalspace.policy' }, crypto.randomUUID(), f.owner.incarnation);
        if (mode === 'final-database') env.ALTERAN_DB = new Proxy(f.env.ALTERAN_DB, {});
      });
      const request = await signedPolicyRequest(f, target, { env: watched.env });
      const response = await GET(policyContext(watched.env, request));
      expect(watched.called()).toBe(true);
      expect(response.status).toBe(401);
      const body = await response.text();
      expect(body).not.toContain('personalspace');
      expect(body).not.toContain('SpaceNotFound');
    }
  });
});
