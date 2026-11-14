import { sqliteTable, text, integer, blob, index, primaryKey, uniqueIndex, check } from 'drizzle-orm/sqlite-core';
import { sql } from 'drizzle-orm';
export { oauth_replay_clock } from './schema-oauth-clock';

export const secret = sqliteTable('secret', {
  key: text('key').primaryKey().notNull(),
  value: text('value').notNull(),
  updatedAt: integer('updated_at', { mode: 'number' }).notNull(),
}, (table) => ({
  replayExpiry: index('oauth_replay_expiry').on(sql`(CASE WHEN json_valid(${table.value}) THEN CASE
    WHEN ${table.key} GLOB 'oauth:dpop:jti:*'
      AND json_type(${table.value}, '$.exp') IN ('integer', 'real')
      AND json_type(${table.value}, '$.iat') IN ('integer', 'real')
      THEN MAX(CAST(json_extract(${table.value}, '$.exp') AS REAL), CAST(json_extract(${table.value}, '$.iat') AS REAL) + 300)
    WHEN ${table.key} GLOB 'oauth:client-assertion:jti:*'
      AND json_type(${table.value}, '$.exp') IN ('integer', 'real')
      THEN CAST(json_extract(${table.value}, '$.exp') AS REAL)
    ELSE NULL END ELSE NULL END)`, table.key).where(sql`${table.key} GLOB 'oauth:dpop:jti:*' OR ${table.key} GLOB 'oauth:client-assertion:jti:*'`),
}));

export const account = sqliteTable('account', {
  did: text('did').primaryKey().notNull(),
  handle: text('handle').notNull(),
  passwordScrypt: text('password_scrypt'),
  email: text('email'),
  createdAt: integer('created_at', { mode: 'number' }).notNull(),
  updatedAt: integer('updated_at', { mode: 'number' }).notNull(),
  spaceIncarnation: text('space_incarnation'),
}, (table) => ({
  handleIdx: uniqueIndex('account_handle_unique').on(table.handle),
  spaceIncarnation: uniqueIndex('account_space_incarnation_unique').on(table.spaceIncarnation),
}));

export const account_space_incarnation_init = sqliteTable('account_space_incarnation_init', {
  id: integer('id').primaryKey().notNull(),
  did: text('did').notNull(),
  incarnation: text('incarnation').notNull(),
}, (table) => ({
  singleton: check('account_space_incarnation_init_singleton', sql`${table.id} = 1`),
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
  clientAuthKeyBinding: text('client_auth_key_binding'),
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

export const oauth_space_grant = sqliteTable('oauth_space_grant', {
  sessionId: text('session_id').primaryKey().notNull().references(() => oauth_session.id),
  snapshot: text('snapshot').notNull(),
  digest: text('digest').notNull(),
  createdAt: integer('created_at').notNull(),
}, (table) => ({
  validSession: check('oauth_space_grant_session_size', sql`length(CAST(${table.sessionId} AS BLOB)) BETWEEN 1 AND 128`),
  validSnapshot: check('oauth_space_grant_snapshot', sql`length(CAST(${table.snapshot} AS BLOB)) BETWEEN 1 AND 65536 AND json_valid(${table.snapshot})`),
  validDigest: check('oauth_space_grant_digest', sql`length(${table.digest}) = 64 AND ${table.digest} NOT GLOB '*[^0-9a-f]*'`),
  validCreated: check('oauth_space_grant_created', sql`typeof(${table.createdAt}) = 'integer' AND ${table.createdAt} BETWEEN 0 AND 9007199254740991`),
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

export const space_personal_policy = sqliteTable('space_personal_policy', {
  spaceRef: text('space_ref').primaryKey().notNull(),
  authorityDid: text('authority_did').notNull(),
  authorityIncarnation: text('authority_incarnation'),
  policyType: text('policy_type').notNull(),
  creationNonce: text('creation_nonce').notNull(),
  notificationState: text('notification_state').notNull(),
  createdAt: integer('created_at').notNull(),
}, (table) => ({
  nonce: uniqueIndex('space_personal_policy_creation_nonce').on(table.creationNonce),
  incarnation: index('space_personal_policy_bound_incarnation').on(table.authorityIncarnation)
    .where(sql`${table.authorityIncarnation} IS NOT NULL`),
  policy: check('space_personal_policy_type', sql`${table.policyType} = 'com.atproto.personalspace.policy'`),
  notifications: check('space_personal_policy_notifications', sql`${table.notificationState} = 'none'`),
}));

export const space_personal_creation_attempt = sqliteTable('space_personal_creation_attempt', {
  nonce: text('nonce').primaryKey().notNull(),
  spaceRef: text('space_ref').notNull(),
  authorityDid: text('authority_did').notNull(),
  authorityIncarnation: text('authority_incarnation'),
  spaceType: text('space_type').notNull(),
  skey: text('skey').notNull(),
  createdAt: integer('created_at').notNull(),
}, (table) => ({
  space: uniqueIndex('space_personal_creation_attempt_space').on(table.spaceRef),
  incarnation: index('space_personal_creation_bound_incarnation').on(table.authorityIncarnation)
    .where(sql`${table.authorityIncarnation} IS NOT NULL`),
}));

export const space_personal_deletion_job = sqliteTable('space_personal_deletion_job', {
  nonce: text('nonce').primaryKey().notNull(),
  spaceRef: text('space_ref').notNull(),
  authorityDid: text('authority_did').notNull(),
  epochId: text('epoch_id'),
  status: text('status').notNull(),
  phase: text('phase').notNull(),
  sequence: integer('sequence').notNull(),
  lastStepNonce: text('last_step_nonce'),
  lastStepPhase: text('last_step_phase'),
  lastStepCount: integer('last_step_count').notNull(),
  createdAt: integer('created_at').notNull(),
}, (table) => ({
  space: uniqueIndex('space_personal_deletion_job_space').on(table.spaceRef),
  status: check('space_personal_deletion_job_status', sql`${table.status} IN ('deleting', 'complete')`),
  phase: check('space_personal_deletion_job_phase', sql`${table.phase} IN ('records', 'versions', 'ops', 'done')`),
  counts: check('space_personal_deletion_job_counts', sql`${table.sequence} >= 0 AND ${table.lastStepCount} BETWEEN 0 AND 32`),
}));

export const space_personal_deletion_attempt = sqliteTable('space_personal_deletion_attempt', {
  nonce: text('nonce').primaryKey().notNull(),
  jobNonce: text('job_nonce').notNull(),
  spaceRef: text('space_ref').notNull(),
  authorityDid: text('authority_did').notNull(),
  epochId: text('epoch_id'),
  phase: text('phase').notNull(),
  sequence: integer('sequence').notNull(),
  status: text('status').notNull(),
  maximumCount: integer('maximum_count').notNull(),
  expectedCount: integer('expected_count').notNull(),
  expectedBytes: integer('expected_bytes').notNull(),
}, (table) => ({
  job: uniqueIndex('space_personal_deletion_attempt_job').on(table.jobNonce),
  owner: index('space_personal_deletion_attempt_owner').on(table.spaceRef, table.authorityDid),
  status: check('space_personal_deletion_attempt_status', sql`${table.status} IN ('building', 'sealed')`),
  counts: check('space_personal_deletion_attempt_counts', sql`${table.sequence} >= 0 AND ${table.maximumCount} BETWEEN 1 AND 32 AND ${table.expectedCount} BETWEEN 0 AND ${table.maximumCount} AND ${table.expectedBytes} BETWEEN 0 AND 4194304`),
}));

export const space_personal_deletion_candidate = sqliteTable('space_personal_deletion_candidate', {
  attemptNonce: text('attempt_nonce').notNull(),
  rowId: integer('row_id').notNull(),
  byteSize: integer('byte_size').notNull(),
}, (table) => ({
  pk: primaryKey({ columns: [table.attemptNonce, table.rowId] }),
  bytes: check('space_personal_deletion_candidate_bytes', sql`${table.byteSize} BETWEEN 0 AND 1048576`),
}));

export const space_repo = sqliteTable('space_repo', {
  spaceRef: text('space_ref').notNull(),
  repoDid: text('repo_did').notNull(),
  rev: text('rev'),
  setHash: blob('set_hash', { mode: 'buffer' }).notNull(),
  generation: integer('generation').notNull(),
  mutationId: text('mutation_id').notNull(),
  activeEpochId: text('active_epoch_id'),
}, (table) => ({
  pk: primaryKey({ columns: [table.spaceRef, table.repoDid] }),
  hashSize: check('space_repo_hash_size', sql`length(${table.setHash}) = 2048`),
}));

export const space_epoch = sqliteTable('space_epoch', {
  id: text('id').primaryKey().notNull(),
  spaceRef: text('space_ref').notNull(),
  repoDid: text('repo_did').notNull(),
  ownerIncarnation: text('owner_incarnation'),
  state: text('state').notNull(),
  createdAt: integer('created_at').notNull(),
  verifiedJobId: text('verified_job_id'),
  activationNonce: text('activation_nonce'),
}, (table) => ({
  activeOwner: uniqueIndex('space_epoch_active_owner').on(table.spaceRef, table.repoDid)
    .where(sql`${table.state} = 'active'`),
  spaceOwner: index('space_epoch_space_owner').on(table.spaceRef, table.repoDid, table.id),
  incarnation: index('space_epoch_bound_incarnation').on(table.ownerIncarnation)
    .where(sql`${table.ownerIncarnation} IS NOT NULL`),
  validState: check('space_epoch_state', sql`${table.state} in ('active', 'quarantined', 'retired', 'deleting')`),
}));

export const space_record_version = sqliteTable('space_record_version', {
  epochId: text('epoch_id').notNull(),
  spaceRef: text('space_ref').notNull(),
  repoDid: text('repo_did').notNull(),
  path: text('path').notNull(),
  collection: text('collection').notNull(),
  rkey: text('rkey').notNull(),
  fromGeneration: integer('from_generation').notNull(),
  untilGeneration: integer('until_generation'),
  cid: text('cid').notNull(),
  valueCbor: blob('value_cbor', { mode: 'buffer' }).notNull(),
  valueSize: integer('value_size').notNull(),
  repoRev: text('repo_rev').notNull(),
}, (table) => ({
  pk: primaryKey({ columns: [table.epochId, table.path, table.fromGeneration] }),
  currentPath: uniqueIndex('space_record_version_current_path').on(table.epochId, table.path)
    .where(sql`${table.untilGeneration} IS NULL`),
  gcCandidates: index('space_record_version_gc_candidates').on(table.epochId, table.spaceRef, table.repoDid,
    table.untilGeneration, table.path, table.fromGeneration).where(sql`${table.untilGeneration} IS NOT NULL`),
  spaceOwnerEpoch: index('space_record_version_space_owner_epoch').on(table.spaceRef, table.repoDid, table.epochId),
  validInterval: check('space_record_version_interval', sql`${table.fromGeneration} >= 1 AND (${table.untilGeneration} IS NULL OR ${table.untilGeneration} > ${table.fromGeneration})`),
  validPath: check('space_record_version_path', sql`${table.path} = ${table.collection} || '/' || ${table.rkey}`),
  validSize: check('space_record_version_size', sql`${table.valueSize} = length(${table.valueCbor}) AND ${table.valueSize} > 0 AND ${table.valueSize} <= 1048576`),
}));

export const space_snapshot_lease = sqliteTable('space_snapshot_lease', {
  id: text('id').primaryKey().notNull(),
  token: text('token').notNull(),
  renewalNonce: text('renewal_nonce').notNull(),
  spaceRef: text('space_ref').notNull(),
  repoDid: text('repo_did').notNull(),
  epochId: text('epoch_id').notNull(),
  generation: integer('generation').notNull(),
  rev: text('rev').notNull(),
  setHash: blob('set_hash', { mode: 'buffer' }).notNull(),
  expiresAt: integer('expires_at').notNull(),
  maximumExpiresAt: integer('maximum_expires_at').notNull(),
}, (table) => ({
  epochExpiry: index('space_snapshot_lease_epoch_expiry').on(table.epochId, table.expiresAt, table.generation),
  epochGeneration: index('space_snapshot_lease_epoch_generation').on(table.epochId, table.spaceRef, table.repoDid, table.generation),
  ownerExpiry: index('space_snapshot_lease_owner_expiry').on(table.spaceRef, table.repoDid, table.expiresAt, table.id),
  ownerMaximumExpiry: index('space_snapshot_lease_owner_maximum_expiry').on(table.spaceRef, table.repoDid, table.maximumExpiresAt, table.id),
  expiry: index('space_snapshot_lease_expiry').on(table.expiresAt, table.id),
  maximumExpiry: index('space_snapshot_lease_maximum_expiry').on(table.maximumExpiresAt, table.id),
  hashSize: check('space_snapshot_lease_hash_size', sql`length(${table.setHash}) = 2048`),
}));

export const space_commit_assertion = sqliteTable('space_commit_assertion', {
  mutationId: text('mutation_id').primaryKey().notNull(),
  valid: integer('valid').notNull(),
}, (table) => ({
  validResult: check('space_commit_assertion_valid', sql`${table.valid} = 1`),
}));

export const space_mutation_attempt = sqliteTable('space_mutation_attempt', {
  mutationId: text('mutation_id').primaryKey().notNull(),
  spaceRef: text('space_ref').notNull(),
  repoDid: text('repo_did').notNull(),
  ownerIncarnation: text('owner_incarnation'),
  epochId: text('epoch_id').notNull(),
  generation: integer('generation').notNull(),
  rev: text('rev').notNull(),
  setHash: blob('set_hash', { mode: 'buffer' }).notNull(),
}, (table) => ({
  owner: index('space_mutation_attempt_owner').on(table.spaceRef, table.repoDid),
  incarnation: index('space_mutation_attempt_bound_incarnation').on(table.ownerIncarnation)
    .where(sql`${table.ownerIncarnation} IS NOT NULL`),
  validGeneration: check('space_mutation_attempt_generation', sql`${table.generation} >= 1`),
  hashSize: check('space_mutation_attempt_hash_size', sql`length(${table.setHash}) = 2048`),
}));

export const space_gc_attempt = sqliteTable('space_gc_attempt', {
  id: text('id').primaryKey().notNull(),
  spaceRef: text('space_ref').notNull(),
  repoDid: text('repo_did').notNull(),
  epochId: text('epoch_id').notNull(),
}, (table) => ({
  owner: index('space_gc_attempt_owner').on(table.spaceRef, table.repoDid),
}));

export const space_quarantine_job = sqliteTable('space_quarantine_job', {
  id: text('id').primaryKey().notNull(),
  token: text('token').notNull(),
  renewalNonce: text('renewal_nonce').notNull(),
  spaceRef: text('space_ref').notNull(),
  repoDid: text('repo_did').notNull(),
  epochId: text('epoch_id').notNull(),
  authorityDid: text('authority_did').notNull(),
  spaceType: text('space_type').notNull(),
  skey: text('skey').notNull(),
  generation: integer('generation').notNull(),
  mutationId: text('mutation_id').notNull(),
  rev: text('rev').notNull(),
  expectedHash: blob('expected_hash', { mode: 'buffer' }).notNull(),
  accumulatedHash: blob('accumulated_hash', { mode: 'buffer' }).notNull(),
  cursor: text('cursor').notNull(),
  sequence: integer('sequence').notNull(),
  recordCount: integer('record_count').notNull(),
  leaseUntil: integer('lease_until').notNull(),
  status: text('status').notNull(),
  activationNonce: text('activation_nonce'),
  failureReason: text('failure_reason'),
  createdAt: integer('created_at').notNull(),
}, (table) => ({
  ownerEpoch: uniqueIndex('space_quarantine_job_owner_epoch').on(table.spaceRef, table.repoDid, table.epochId),
  validHashes: check('space_quarantine_job_hashes', sql`length(${table.expectedHash}) = 2048 AND length(${table.accumulatedHash}) = 2048`),
  validCounts: check('space_quarantine_job_counts', sql`${table.generation} >= 1 AND ${table.sequence} >= 0 AND ${table.recordCount} >= 0`),
  validStatus: check('space_quarantine_job_status', sql`${table.status} IN ('running', 'complete', 'activating', 'active', 'failed')`),
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
  pathIdx: index('space_record_path_idx').on(table.spaceRef, table.repoDid, sql`(${table.collection} || '/' || ${table.rkey}) COLLATE BINARY`),
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
  reservation_nonce: text('reservation_nonce'),
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

export const private_blob_staging = sqliteTable('private_blob_staging', {
  id: text('id').primaryKey().notNull(),
  token: text('token').notNull(),
  repoDid: text('repo_did').notNull(),
  accountIncarnation: text('account_incarnation').notNull(),
  objectKey: text('object_key').notNull(),
  state: text('state').notNull(),
  reservedBytes: integer('reserved_bytes').notNull(),
  claimNonce: text('claim_nonce'),
  cid: text('cid'),
  digest: text('digest'),
  size: integer('size'),
  mimeType: text('mime_type'),
  r2Version: text('r2_version'),
  etag: text('etag'),
}, (table) => ({
  objectKey: uniqueIndex('private_blob_staging_object_key').on(table.objectKey),
  owner: index('private_blob_staging_owner').on(table.repoDid),
  state: check('private_blob_staging_state', sql`${table.state} IN ('reserved', 'putting', 'ready', 'uncertain')`),
  charge: check('private_blob_staging_charge', sql`typeof(${table.reservedBytes}) = 'integer' AND ${table.reservedBytes} = 5242880`),
}));
