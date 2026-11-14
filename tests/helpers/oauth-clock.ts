import type { Env } from '../../src/env';

/** Simulate a delayed or lost response after D1 has committed the batch. */
export function afterReplayBatch(env: Env, after: () => void): Env {
  const database = env.ALTERAN_DB;
  const wrapped = new Proxy(database, {
    get(target, property) {
      if (property === 'batch') {
        return async (statements: Parameters<typeof database.batch>[0]) => {
          const result = await target.batch(statements);
          after();
          return result;
        };
      }
      const value = Reflect.get(target, property, target);
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });
  return { ...env, ALTERAN_DB: wrapped };
}

export async function advanceReplayClock(env: Env, seconds: number): Promise<void> {
  await env.ALTERAN_DB.prepare('UPDATE oauth_replay_clock SET seconds = ? WHERE id = 1')
    .bind(seconds).run();
}
