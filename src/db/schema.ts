import { sqliteTable, text, integer, index, primaryKey, uniqueIndex } from 'drizzle-orm/sqlite-core';

export const secret = sqliteTable('secret', {
  key: text('key').primaryKey().notNull(),
  value: text('value').notNull(),
  updatedAt: integer('updated_at', { mode: 'number' }).notNull(),
});

export const account = sqliteTable('account', {
  did: text('did').primaryKey().notNull(),
  handle: text('handle').notNull(),
  passwordScrypt: text('password_scrypt'),
  email: text('email'),
  createdAt: integer('created_at', { mode: 'number' }).notNull(),
  updatedAt: integer('updated_at', { mode: 'number' }).notNull(),
}, (table) => ({
  handleIdx: uniqueIndex('account_handle_unique').on(table.handle),
}));

export const refresh_token_store = sqliteTable('refresh_token', {
  id: text('id').primaryKey().notNull(),
  did: text('did').notNull(),
  expiresAt: integer('expires_at', { mode: 'number' }).notNull(),
  appPasswordName: text('app_password_name'),
  nextId: text('next_id'),
}, (table) => ({
  didIdx: index('refresh_token_did_idx').on(table.did),
}));

export const repo_root = sqliteTable('repo_root', {
  did: text('did').primaryKey().notNull(),
  commitCid: text('commit_cid').notNull(),
  rev: text('rev').notNull(), // TID format (e.g., "3m2biurz7cl27")
});

export const record = sqliteTable('record', {
  uri: text('uri').primaryKey().notNull(),
  did: text('did').notNull(),
  cid: text('cid').notNull(),
  json: text('json').notNull(),
  createdAt: integer('created_at', { mode: 'number' }).default(0),
}, (table) => ({
  // Index for collection queries (did + collection extracted from uri)
  didIdx: index('record_did_idx').on(table.did),
  // Index for CID lookups (used in getRecordsByCids)
  cidIdx: index('record_cid_idx').on(table.cid),
}));

export const blob_ref = sqliteTable('blob', {
  cid: text('cid').primaryKey().notNull(),
  did: text('did').notNull(),
  key: text('key').notNull(),
  mime: text('mime').notNull(),
  size: integer('size').notNull(),
});

export const blob_usage = sqliteTable('blob_usage', {
  recordUri: text('record_uri').notNull(),
  key: text('key').notNull(),
}, (table) => ({
  // Composite primary key on recordUri and key
  pk: primaryKey({ columns: [table.recordUri, table.key] }),
  // Index for GC queries (finding blobs by record)
  recordUriIdx: index('blob_usage_record_uri_idx').on(table.recordUri),
}));

// Commit log stores full commit history for firehose and sync
// Pruning policy: Keep last N commits (default: 10000) to prevent unbounded growth
// Older commits can be safely removed as they're not needed for sync after a certain point
// The MST and current repo state are preserved independently
export const commit_log = sqliteTable('commit_log', {
  seq: integer('seq').primaryKey(),
  cid: text('cid').notNull(),
  rev: text('rev').notNull(), // TID format
  data: text('data').notNull(), // Full commit object as JSON
  sig: text('sig').notNull(), // Signature as base64
  ts: integer('ts').notNull(),
}, (table) => ({
  // Index for pruning old commits
  seqIdx: index('commit_log_seq_idx').on(table.seq),
}));

// Blockstore stores MST nodes (Merkle Search Tree blocks)
// Each MST node is stored as a CBOR-encoded block identified by its CID
// GC policy: Remove blocks not referenced by recent commits (keep blocks from last N commits)
export const blockstore = sqliteTable('blockstore', {
  cid: text('cid').primaryKey(),
  bytes: text('bytes'),
});

export const login_attempts = sqliteTable('login_attempts', {
  ip: text('ip').primaryKey().notNull(),
  attempts: integer('attempts').notNull().default(0),
  locked_until: integer('locked_until'),
  last_attempt: integer('last_attempt').notNull(),
});

// Blob quota tracking per DID
export const blob_quota = sqliteTable('blob_quota', {
  did: text('did').primaryKey().notNull(),
  total_bytes: integer('total_bytes').notNull().default(0),
  blob_count: integer('blob_count').notNull().default(0),
  updated_at: integer('updated_at').notNull(),
});

// Account state for migration support (single-user PDS). The active flag
// stays for legacy reads, but the full FSM is recovered from
// (active, status, suspended_until) via fromRow in src/lib/account-state.ts.
export const account_state = sqliteTable('account_state', {
  did: text('did').primaryKey().notNull(),
  active: integer('active', { mode: 'boolean' }).notNull().default(false),
  status: text('status'),
  suspended_until: integer('suspended_until'),
  created_at: integer('created_at').notNull(),
});

export type RecordRow = typeof record.$inferSelect;
export type NewRecordRow = typeof record.$inferInsert;
