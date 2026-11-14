import { sqliteTable, text, integer, blob, index, primaryKey, uniqueIndex, check } from 'drizzle-orm/sqlite-core';
import { sql } from 'drizzle-orm';

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
  tokenKind: text('token_kind').notNull().default('legacy'),
  oauthSessionId: text('oauth_session_id'),
  clientId: text('client_id'),
  clientAuthMethod: text('client_auth_method'),
  clientAuthKeyId: text('client_auth_key_id'),
  dpopJkt: text('dpop_jkt'),
  oauthScope: text('oauth_scope'),
  accessJti: text('access_jti'),
  revokedAt: integer('revoked_at', { mode: 'number' }),
}, (table) => ({
  didIdx: index('refresh_token_did_idx').on(table.did),
  oauthSessionIdx: index('refresh_token_oauth_session_idx').on(table.oauthSessionId),
  accessJtiIdx: index('refresh_token_access_jti_idx').on(table.accessJti),
}));

export const oauth_session = sqliteTable('oauth_session', {
  id: text('id').primaryKey().notNull(),
  did: text('did').notNull(),
  clientId: text('client_id').notNull(),
  clientAuthMethod: text('client_auth_method').notNull(),
  clientAuthKeyId: text('client_auth_key_id'),
  dpopJkt: text('dpop_jkt').notNull(),
  scope: text('scope').notNull(),
  currentRefreshTokenId: text('current_refresh_token_id').notNull(),
  accessJti: text('access_jti').notNull(),
  createdAt: integer('created_at', { mode: 'number' }).notNull(),
  updatedAt: integer('updated_at', { mode: 'number' }).notNull(),
  expiresAt: integer('expires_at', { mode: 'number' }).notNull(),
  revokedAt: integer('revoked_at', { mode: 'number' }),
}, (table) => ({
  clientIdx: index('oauth_session_client_idx').on(table.clientId),
  currentRefreshIdx: index('oauth_session_current_refresh_idx').on(table.currentRefreshTokenId),
  accessJtiIdx: index('oauth_session_access_jti_idx').on(table.accessJti),
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
  cid: text('cid').notNull(),
  did: text('did').notNull(),
  key: text('key').notNull(),
  mime: text('mime').notNull(),
  size: integer('size').notNull(),
  uploadedAt: integer('uploaded_at', { mode: 'number' }).notNull().default(0),
}, (table) => ({
  pk: primaryKey({ columns: [table.did, table.cid] }),
  keyIdx: index('blob_key_idx').on(table.key),
}));

export const blob_usage = sqliteTable('blob_usage', {
  did: text('did').notNull(),
  recordUri: text('record_uri').notNull(),
  key: text('key').notNull(),
  cid: text('cid').notNull(),
  repoRev: text('repo_rev').notNull(),
}, (table) => ({
  // Composite primary key on did, recordUri, and key
  pk: primaryKey({ columns: [table.did, table.recordUri, table.key] }),
  // Index for GC queries (finding blobs by record)
  recordUriIdx: index('blob_usage_record_uri_idx').on(table.did, table.recordUri),
  didKeyIdx: index('blob_usage_did_key_idx').on(table.did, table.key),
  didRepoRevCidIdx: index('blob_usage_did_repo_rev_cid_idx').on(table.did, table.repoRev, table.cid),
}));

export const space = sqliteTable('space', {
  ref: text('space_ref').primaryKey().notNull(),
  authorityDid: text('authority_did').notNull(),
  spaceType: text('space_type').notNull(),
  skey: text('skey').notNull(),
  createdAt: integer('created_at').notNull(),
  deletedAt: integer('deleted_at'),
}, (table) => ({
  authorityTypeIdx: index('space_authority_type_idx').on(table.authorityDid, table.spaceType, table.ref),
}));

export const space_repo = sqliteTable('space_repo', {
  spaceRef: text('space_ref').notNull(),
  repoDid: text('repo_did').notNull(),
  rev: text('rev'),
  setHash: blob('set_hash', { mode: 'buffer' }).notNull(),
  generation: integer('generation').notNull(),
  mutationId: text('mutation_id').notNull(),
}, (table) => ({
  pk: primaryKey({ columns: [table.spaceRef, table.repoDid] }),
  hashSize: check('space_repo_hash_size', sql`length(${table.setHash}) = 2048`),
}));

export const space_record = sqliteTable('space_record', {
  spaceRef: text('space_ref').notNull(),
  repoDid: text('repo_did').notNull(),
  collection: text('collection').notNull(),
  rkey: text('rkey').notNull(),
  cid: text('cid').notNull(),
  valueCbor: blob('value_cbor', { mode: 'buffer' }).notNull(),
  repoRev: text('repo_rev').notNull(),
}, (table) => ({
  pk: primaryKey({ columns: [table.spaceRef, table.repoDid, table.collection, table.rkey] }),
  cidIdx: index('space_record_cid_idx').on(table.spaceRef, table.repoDid, table.cid),
}));

export const space_op = sqliteTable('space_op', {
  spaceRef: text('space_ref').notNull(),
  repoDid: text('repo_did').notNull(),
  rev: text('rev').notNull(),
  ordinal: integer('ordinal').notNull(),
  collection: text('collection').notNull(),
  rkey: text('rkey').notNull(),
  cid: text('cid'),
  prev: text('prev'),
}, (table) => ({
  pk: primaryKey({ columns: [table.spaceRef, table.repoDid, table.rev, table.ordinal] }),
}));

export const space_blob_usage = sqliteTable('space_blob_usage', {
  spaceRef: text('space_ref').notNull(),
  repoDid: text('repo_did').notNull(),
  collection: text('collection').notNull(),
  rkey: text('rkey').notNull(),
  cid: text('cid').notNull(),
  key: text('key').notNull(),
}, (table) => ({
  pk: primaryKey({ columns: [table.spaceRef, table.repoDid, table.collection, table.rkey, table.cid] }),
  retentionIdx: index('space_blob_usage_retention_idx').on(table.repoDid, table.key),
  cidRetentionIdx: index('space_blob_usage_cid_retention_idx').on(table.repoDid, table.cid),
  spaceCidIdx: index('space_blob_usage_space_cid_idx').on(table.spaceRef, table.repoDid, table.cid),
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

export const app_password = sqliteTable('app_password', {
  did: text('did').notNull(),
  name: text('name').notNull(),
  passwordScrypt: text('password_scrypt').notNull(),
  privileged: integer('privileged', { mode: 'boolean' }).notNull().default(false),
  createdAt: integer('created_at', { mode: 'number' }).notNull(),
}, (table) => ({
  pk: primaryKey({ columns: [table.did, table.name] }),
  didIdx: index('app_password_did_idx').on(table.did),
}));

export type AppPasswordRow = typeof app_password.$inferSelect;

export type RecordRow = typeof record.$inferSelect;
export type NewRecordRow = typeof record.$inferInsert;
