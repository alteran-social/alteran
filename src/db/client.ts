// Types via tsconfig.app.json
import { drizzle } from 'drizzle-orm/d1';
import type { Env } from '../env';

export function getDb(env: Env) {
  return drizzle(env.ALTERAN_DB);
}
