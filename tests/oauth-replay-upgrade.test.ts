import { expect } from '@std/expect';
import type { D1Database } from '@cloudflare/workers-types';
import { Miniflare } from 'miniflare';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it } from './helpers/bdd';
import type { Env } from '../src/env';
import { cleanupExpiredOAuthReplaySecrets, OAUTH_REPLAY_SWEEP_SQL } from '../src/db/oauth-replay';

describe('OAuth replay index migration', () => {
  it('indexes and safely cleans populated legacy replay data on upgrade', async () => {
    const service = new Miniflare({
      d1Databases: { DB: ':memory:' }, compatibilityDate: '2025-10-02',
      script: "export default { fetch: () => new Response('ok') }", modules: true,
    });
    await service.ready;
    const database = await service.getD1Database('DB') as unknown as D1Database;
    const directory = join(import.meta.dirname!, '..', 'migrations');
    const names = readdirSync(directory).filter((name) => name.endsWith('.sql')).sort();
    const apply = async (name: string) => {
      for (const chunk of readFileSync(join(directory, name), 'utf8').split('--> statement-breakpoint')) {
        if (chunk.trim()) await database.exec(chunk.trim().replace(/\n/g, ' '));
      }
    };
    try {
      for (const name of names.filter((name) => name < '0027')) await apply(name);
      const clock = await database.prepare('SELECT seconds FROM oauth_replay_clock WHERE id = 1')
        .first<{ seconds: number }>();
      if (!clock) throw new Error('Missing replay clock');
      const stale = JSON.stringify({ iat: clock.seconds - 700, exp: clock.seconds - 200 });
      const live = JSON.stringify({ iat: clock.seconds - 10, exp: clock.seconds + 300 });
      const entries = [
        ['oauth:dpop:jti:authz:old', stale],
        ['oauth:dpop:jti:authz:live', live],
        ['oauth:dpop:jti:authz:malformed', '{'],
        ['oauth:dpop:jti:authz:unknown', JSON.stringify({ iat: 'unknown', exp: 1 })],
        ['oauth:client-assertion:jti:client:old', JSON.stringify({ exp: clock.seconds - 0.5 })],
      ];
      await database.batch(entries.map(([key, value]) => database.prepare(
        'INSERT INTO secret (key, value, updated_at) VALUES (?, ?, 0)',
      ).bind(key, value)));
      for (const name of names.filter((name) => name >= '0027')) await apply(name);
      const plan = await database.prepare(`EXPLAIN QUERY PLAN ${OAUTH_REPLAY_SWEEP_SQL}`)
        .bind('0'.repeat(32), clock.seconds, 512).all<{ detail: string }>();
      expect(plan.results.some(({ detail }) => detail.includes('oauth_replay_expiry') && detail.includes('SEARCH'))).toBe(true);
      const env = { ALTERAN_DB: database } as unknown as Env;
      expect(await cleanupExpiredOAuthReplaySecrets(env)).toBe(2);
      const result = await database.prepare("SELECT key FROM secret WHERE key GLOB 'oauth:*:jti:*' ORDER BY key")
        .all<{ key: string }>();
      expect(result.results.map(({ key }) => key)).toEqual([
        'oauth:dpop:jti:authz:live',
        'oauth:dpop:jti:authz:malformed',
        'oauth:dpop:jti:authz:unknown',
      ]);
    } finally {
      await service.dispose();
    }
  });
});
