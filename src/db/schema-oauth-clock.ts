import { check, integer, sqliteTable, text } from 'drizzle-orm/sqlite-core';
import { sql } from 'drizzle-orm';

export const oauth_replay_clock = sqliteTable('oauth_replay_clock', {
  id: integer('id').primaryKey().notNull(),
  seconds: integer('seconds', { mode: 'number' }).notNull(),
  nonce: text('nonce').notNull(),
}, (table) => ({
  singleton: check('oauth_replay_clock_singleton', sql`${table.id} = 1`),
  validSeconds: check('oauth_replay_clock_seconds', sql`typeof(${table.seconds}) = 'integer' AND ${table.seconds} BETWEEN 0 AND 9007199254740991`),
  validNonce: check('oauth_replay_clock_nonce', sql`length(${table.nonce}) = 32`),
}));
