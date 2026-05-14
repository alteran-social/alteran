import { lexicons, jsonToLex } from '@atproto/api';
import { isValidNsid, isValidRecordKey, isValidTid } from '@atproto/syntax';
import { CID } from 'multiformats/cid';
import type { Env } from '../env';
import { resolveSecret } from './secrets';
import { generateTid } from './commit';
import { RepoManager } from '../services/repo-manager';
import { cidForRecord } from '../services/repo/blockstore-ops';
import { RepoWriteLimitError } from './repo-write-limits';

export type ValidationStatus = 'valid' | 'unknown' | undefined;
export type RepoWriteAction = 'create' | 'update' | 'delete';

export type PreparedRecordWrite = {
  action: Extract<RepoWriteAction, 'create' | 'update'>;
  collection: string;
  rkey: string;
  record: Record<string, unknown>;
  validationStatus: ValidationStatus;
  blobKeys: string[];
};

export type PreparedDeleteWrite = {
  action: 'delete';
  collection: string;
  rkey: string;
};

export type PreparedWrite = PreparedRecordWrite | PreparedDeleteWrite;

export type RepoWriteContext = {
  did: string;
  handle: string | undefined;
  currentCommitCid: string | null;
  repo: RepoManager;
};

export type RepoWriteContextWithSwap = RepoWriteContext & {
  expectedCommitCid: string | null | undefined;
};

type AuthLike = { did: string };

export type RequestedWriteAuthorization = {
  collection: string;
  action: RepoWriteAction;
};

export class RepoWriteError extends Error {
  constructor(
    public readonly error: string,
    message: string,
    public readonly status = 400,
  ) {
    super(message);
  }

  toResponse(): Response {
    return jsonError(this.error, this.message, this.status);
  }
}

export function jsonError(error: string, message?: string, status = 400): Response {
  return new Response(JSON.stringify({
    error,
    ...(message ? { message } : {}),
  }), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

export function invalidSwap(message = 'Invalid swap'): Response {
  return jsonError('InvalidSwap', message, 400);
}

export function handleRepoWriteError(error: unknown): Response {
  if (error instanceof RepoWriteError) return error.toResponse();
  if (isRepoBlobNotFound(error)) {
    return jsonError('BlobNotFound', 'blob not found', 400);
  }
  if (isRepoCommitConflict(error)) {
    return jsonError('InvalidSwap', 'repo head changed', 400);
  }
  if (error instanceof RepoWriteLimitError) {
    return jsonError('InvalidRequest', error.message, 400);
  }
  throw error;
}

export function hasSwapCommit(input: Record<string, unknown>): boolean {
  return Object.prototype.hasOwnProperty.call(input, 'swapCommit');
}

export async function retryNoSwapCommit<T>(
  input: Record<string, unknown>,
  write: () => Promise<T>,
): Promise<T> {
  const canRetry = !hasSwapCommit(input);
  const maxAttempts = canRetry ? 3 : 1;
  let lastError: unknown;
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    try {
      return await write();
    } catch (error) {
      lastError = error;
      if (!canRetry || !isRepoCommitConflict(error)) break;
    }
  }
  throw lastError;
}

export async function buildRepoWriteContext(
  env: Env,
  auth: AuthLike,
  repoValue: unknown,
): Promise<RepoWriteContext> {
  const did = await resolveSecret(env.PDS_DID);
  if (!did) throw new RepoWriteError('InvalidRequest', 'PDS_DID is not configured');
  const handle = await resolveSecret(env.PDS_HANDLE);

  if (auth.did !== did) {
    throw new RepoWriteError('InvalidRequest', 'authenticated user does not own this repo');
  }

  if (typeof repoValue !== 'string' || repoValue.length === 0) {
    throw new RepoWriteError('InvalidRequest', 'repo is required');
  }
  const normalizedRepo = repoValue.toLowerCase();
  const normalizedHandle = typeof handle === 'string' ? handle.toLowerCase() : undefined;
  if (repoValue !== did && normalizedRepo !== normalizedHandle) {
    throw new RepoWriteError('InvalidRequest', 'repo is not hosted by this PDS');
  }

  return {
    did,
    handle,
    currentCommitCid: await getCurrentCommitCid(env, did),
    repo: new RepoManager(env),
  };
}

export async function prepareCreateRecord(
  env: Env,
  auth: AuthLike,
  input: unknown,
): Promise<RepoWriteContextWithSwap & { write: PreparedRecordWrite }> {
  const body = assertRepoWriteInput('com.atproto.repo.createRecord', input);
  const ctx = await buildRepoWriteContext(env, auth, body.repo);
  const expectedCommitCid = expectedCommitCidForRequest(body, ctx.currentCommitCid);

  const collection = requireString(body.collection, 'collection');
  const rkey = typeof body.rkey === 'string' ? body.rkey : generateTid();
  validatePath(collection, rkey);

  const currentCid = await ctx.repo.getRecordCid(collection, rkey);
  if (currentCid) {
    throw new RepoWriteError('InvalidRequest', 'record already exists');
  }

  return {
    ...ctx,
    expectedCommitCid,
    write: await prepareRecordWrite(env, ctx.did, {
      action: 'create',
      collection,
      rkey,
      record: body.record,
      validate: body.validate,
    }),
  };
}

export async function preparePutRecord(
  env: Env,
  auth: AuthLike,
  input: unknown,
): Promise<RepoWriteContextWithSwap & { write: PreparedRecordWrite }> {
  const body = assertRepoWriteInput('com.atproto.repo.putRecord', input);
  const ctx = await buildRepoWriteContext(env, auth, body.repo);

  const collection = requireString(body.collection, 'collection');
  const rkey = requireString(body.rkey, 'rkey');
  validatePath(collection, rkey);

  const currentCid = await ctx.repo.getRecordCid(collection, rkey);
  const write = await prepareRecordWrite(env, ctx.did, {
    action: currentCid ? 'update' : 'create',
    collection,
    rkey,
    record: body.record,
    validate: body.validate,
  });
  const candidateCid = await cidForRecord(write.record);
  const expectedCommitCid = expectedCommitCidForRequest(body, ctx.currentCommitCid);
  checkSwapRecord(body.swapRecord, currentCid, true);

  return {
    ...ctx,
    expectedCommitCid,
    write,
  };
}

export async function prepareDeleteRecord(
  env: Env,
  auth: AuthLike,
  input: unknown,
): Promise<RepoWriteContextWithSwap & { write: PreparedDeleteWrite; currentCid: CID | null }> {
  const body = assertRepoWriteInput('com.atproto.repo.deleteRecord', input);
  const ctx = await buildRepoWriteContext(env, auth, body.repo);

  const collection = requireString(body.collection, 'collection');
  const rkey = requireString(body.rkey, 'rkey');
  validatePath(collection, rkey);

  const currentCid = await ctx.repo.getRecordCid(collection, rkey);
  const expectedCommitCid = expectedCommitCidForRequest(body, ctx.currentCommitCid);
  checkSwapRecord(body.swapRecord, currentCid, false);

  return {
    ...ctx,
    expectedCommitCid,
    currentCid,
    write: { action: 'delete', collection, rkey },
  };
}

export async function prepareApplyWrites(
  env: Env,
  auth: AuthLike,
  input: unknown,
): Promise<RepoWriteContextWithSwap & { writes: PreparedWrite[] }> {
  const body = assertRepoWriteInput('com.atproto.repo.applyWrites', input);
  const ctx = await buildRepoWriteContext(env, auth, body.repo);
  const expectedCommitCid = expectedCommitCidForRequest(body, ctx.currentCommitCid);

  const rawWrites = Array.isArray(body.writes) ? body.writes : [];
  if (rawWrites.length > 200) {
    throw new RepoWriteError('InvalidRequest', 'Too many writes. Max: 200');
  }
  const prepared: PreparedWrite[] = [];
  const state = new Map<string, boolean>();

  for (const raw of rawWrites) {
    const write = raw as Record<string, unknown>;
    const type = write.$type;
    const collection = requireString(write.collection, 'collection');
    const rkey = typeof write.rkey === 'string' ? write.rkey : generateTid();
    validatePath(collection, rkey);
    const path = repoPath(collection, rkey);

    let exists = state.get(path);
    if (exists === undefined) {
      exists = !!(await ctx.repo.getRecordCid(collection, rkey));
    }

    if (type === 'com.atproto.repo.applyWrites#create') {
      if (exists) throw new RepoWriteError('InvalidRequest', 'record already exists');
      const preparedWrite = await prepareRecordWrite(env, ctx.did, {
        action: 'create',
        collection,
        rkey,
        record: write.value,
        validate: body.validate,
      });
      prepared.push(preparedWrite);
      state.set(path, true);
      continue;
    }

    if (type === 'com.atproto.repo.applyWrites#update') {
      if (!exists) throw new RepoWriteError('InvalidRequest', 'record does not exist');
      const preparedWrite = await prepareRecordWrite(env, ctx.did, {
        action: 'update',
        collection,
        rkey,
        record: write.value,
        validate: body.validate,
      });
      prepared.push(preparedWrite);
      state.set(path, true);
      continue;
    }

    if (type === 'com.atproto.repo.applyWrites#delete') {
      prepared.push({ action: 'delete', collection, rkey });
      state.set(path, false);
      continue;
    }

    throw new RepoWriteError('InvalidRequest', 'unsupported write type');
  }

  return { ...ctx, expectedCommitCid, writes: prepared };
}

export function repoPath(collection: string, rkey: string): string {
  return `${collection}/${rkey}`;
}

export function createRecordAuthorizations(
  input: Record<string, any>,
): RequestedWriteAuthorization[] {
  return [{ collection: requireString(input.collection, 'collection'), action: 'create' }];
}

export function putRecordAuthorizations(
  input: Record<string, any>,
): RequestedWriteAuthorization[] {
  const collection = requireString(input.collection, 'collection');
  if (input.swapRecord === null) {
    return [{ collection, action: 'create' }];
  }
  if (typeof input.swapRecord === 'string') {
    return [{ collection, action: 'update' }];
  }
  return [
    { collection, action: 'create' },
    { collection, action: 'update' },
  ];
}

export function deleteRecordAuthorizations(
  input: Record<string, any>,
): RequestedWriteAuthorization[] {
  return [{ collection: requireString(input.collection, 'collection'), action: 'delete' }];
}

export function applyWritesAuthorizations(
  input: Record<string, any>,
): RequestedWriteAuthorization[] {
  const rawWrites = Array.isArray(input.writes) ? input.writes : [];
  return rawWrites.map((raw) => {
    const write = raw as Record<string, unknown>;
    const collection = requireString(write.collection, 'collection');
    switch (write.$type) {
      case 'com.atproto.repo.applyWrites#create':
        return { collection, action: 'create' };
      case 'com.atproto.repo.applyWrites#update':
        return { collection, action: 'update' };
      case 'com.atproto.repo.applyWrites#delete':
        return { collection, action: 'delete' };
      default:
        throw new RepoWriteError('InvalidRequest', 'unsupported write type');
    }
  });
}

export function assertRepoWriteInput(lexUri: string, input: unknown): Record<string, any> {
  try {
    return lexicons.assertValidXrpcInput(lexUri, input) as Record<string, any>;
  } catch (error) {
    throw new RepoWriteError('InvalidRequest', error instanceof Error ? error.message : 'invalid input');
  }
}

function requireString(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new RepoWriteError('InvalidRequest', `${field} is required`);
  }
  return value;
}

function validatePath(collection: string, rkey: string): void {
  if (!isValidNsid(collection)) {
    throw new RepoWriteError('InvalidRequest', 'collection must be a valid NSID');
  }
  if (!isValidRecordKey(rkey)) {
    throw new RepoWriteError('InvalidRequest', 'rkey must be a valid record key');
  }
}

async function prepareRecordWrite(
  env: Env,
  did: string,
  input: {
    action: Extract<RepoWriteAction, 'create' | 'update'>;
    collection: string;
    rkey: string;
    record: unknown;
    validate: unknown;
  },
): Promise<PreparedRecordWrite> {
  const record = validateRawRecord(input.collection, input.record);
  const validationStatus = validateLexiconRecord(
    input.collection,
    input.rkey,
    record,
    input.validate,
  );
  const blobKeys = await validateBlobRefs(env, did, record);
  return { ...input, record, validationStatus, blobKeys };
}

function validateLexiconRecord(
  collection: string,
  rkey: string,
  record: Record<string, unknown>,
  validate: unknown,
): ValidationStatus {
  if (validate === false) return undefined;

  const def = lexicons.getDef(collection);
  const knownRecord = def?.type === 'record' ? def : null;

  if (!knownRecord) {
    if (validate === true) {
      throw new RepoWriteError('InvalidRequest', `Lexicon not found: ${collection}`);
    }
    return 'unknown';
  }

  enforceRecordKeyPolicy(knownRecord.key, rkey);

  let result;
  try {
    result = lexicons.validate(collection, jsonToLex(record));
  } catch (error) {
    throw new RepoWriteError('InvalidRequest', error instanceof Error ? error.message : 'invalid record');
  }
  if (!result.success) {
    throw new RepoWriteError('InvalidRequest', result.error?.message ?? 'invalid record');
  }
  return 'valid';
}

function enforceRecordKeyPolicy(policy: unknown, rkey: string): void {
  if (typeof policy !== 'string' || policy === '' || policy === 'any') return;
  if (policy === 'tid') {
    if (!isValidTid(rkey)) throw new RepoWriteError('InvalidRequest', 'rkey must be a valid TID');
    return;
  }
  if (policy === 'nsid') {
    if (!isValidNsid(rkey)) throw new RepoWriteError('InvalidRequest', 'rkey must be a valid NSID');
    return;
  }
  if (policy.startsWith('literal:')) {
    const expected = policy.slice('literal:'.length);
    if (rkey !== expected) throw new RepoWriteError('InvalidRequest', `rkey must be ${expected}`);
  }
}

type RawRecordValidationOptions = {
  allowLegacyBlobObjects?: boolean;
};

export function validateRawRecord(
  collection: string,
  value: unknown,
  options: RawRecordValidationOptions = {},
): Record<string, unknown> {
  if (!isPlainObject(value)) {
    throw new RepoWriteError('InvalidRequest', 'record must be an object');
  }
  const record = { ...value } as Record<string, unknown>;
  if (record.$type === undefined) {
    throw new RepoWriteError('InvalidRequest', 'record $type is required');
  } else if (record.$type !== collection) {
    throw new RepoWriteError('InvalidRequest', 'record $type must match collection');
  }
  validateRawValue(record, 'record', options);
  return record;
}

function validateRawValue(value: unknown, path: string, options: RawRecordValidationOptions): void {
  if (value === null) return;
  if (typeof value === 'string' || typeof value === 'boolean') return;
  if (typeof value === 'number') {
    if (!Number.isInteger(value)) {
      throw new RepoWriteError('InvalidRequest', `${path} must contain integer numbers`);
    }
    if (!Number.isSafeInteger(value)) {
      throw new RepoWriteError('InvalidRequest', `${path} contains an unsafe integer`);
    }
    return;
  }
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) validateRawValue(value[i], `${path}/${i}`, options);
    return;
  }
  if (!isPlainObject(value)) {
    throw new RepoWriteError('InvalidRequest', `${path} contains an unsupported value`);
  }

  const obj = value as Record<string, unknown>;
  if ('$link' in obj) {
    validateCidLinkObject(obj, path);
    return;
  }
  if ('$bytes' in obj) {
    validateBytesObject(obj, path);
    return;
  }
  if (isLegacyBlobObject(obj)) {
    if (!options.allowLegacyBlobObjects) {
      throw new RepoWriteError('InvalidRequest', `${path} contains a legacy blob object`);
    }
    validateLegacyBlobObject(obj, path);
    return;
  }
  if (obj.$type === 'blob') {
    validateBlobObject(obj, path);
    return;
  }

  for (const [key, child] of Object.entries(obj)) {
    if (key.length === 0) {
      throw new RepoWriteError('InvalidRequest', `${path} contains an empty object key`);
    }
    if (key === '$type' && typeof child !== 'string') {
      throw new RepoWriteError('InvalidRequest', `${path} $type must be a string`);
    }
    validateRawValue(child, `${path}/${key}`, options);
  }
}

function validateCidLinkObject(obj: Record<string, unknown>, path: string): CID {
  const keys = Object.keys(obj);
  if (keys.length !== 1 || typeof obj.$link !== 'string') {
    throw new RepoWriteError('InvalidRequest', `${path} must be a CID link object`);
  }
  if (!obj.$link.startsWith('b') || obj.$link !== obj.$link.toLowerCase()) {
    throw new RepoWriteError('InvalidRequest', `${path} must contain a base32 CID string`);
  }
  let cid;
  try {
    cid = CID.parse(obj.$link);
  } catch {
    throw new RepoWriteError('InvalidRequest', `${path} must contain a valid CID`);
  }
  if (cid.toString() !== obj.$link) {
    throw new RepoWriteError('InvalidRequest', `${path} must contain a base32 CID string`);
  }
  validateDataCid(cid, path);
  return cid;
}

function validateBytesObject(obj: Record<string, unknown>, path: string): void {
  const keys = Object.keys(obj);
  if (keys.length !== 1 || typeof obj.$bytes !== 'string') {
    throw new RepoWriteError('InvalidRequest', `${path} must be a bytes object`);
  }
  if (!isSimpleBase64(obj.$bytes)) {
    throw new RepoWriteError('InvalidRequest', `${path} must contain RFC-4648 base64 bytes`);
  }
}

function validateBlobObject(obj: Record<string, unknown>, path: string): {
  cid: CID;
  mimeType: string;
  size: number;
} {
  const keys = Object.keys(obj).sort();
  if (keys.join('\0') !== ['$type', 'mimeType', 'ref', 'size'].sort().join('\0')) {
    throw new RepoWriteError('InvalidRequest', `${path} must be a regular blob object`);
  }
  if (obj.$type !== 'blob') {
    throw new RepoWriteError('InvalidRequest', `${path} must be a typed blob`);
  }
  if (!isPlainObject(obj.ref)) {
    throw new RepoWriteError('InvalidRequest', `${path}.ref must be a CID link`);
  }
  const cid = validateCidLinkObject(obj.ref as Record<string, unknown>, `${path}/ref`);
  validateRawBlobCid(cid, path);
  if (typeof obj.mimeType !== 'string' || obj.mimeType.length === 0) {
    throw new RepoWriteError('InvalidRequest', `${path}.mimeType must be non-empty`);
  }
  if (typeof obj.size !== 'number' || !Number.isInteger(obj.size) || obj.size < 0) {
    throw new RepoWriteError('InvalidRequest', `${path}.size must be a non-negative integer`);
  }
  return { cid, mimeType: obj.mimeType, size: obj.size };
}

function validateRawBlobCid(cid: CID, path: string): void {
  if (cid.version !== 1 || cid.code !== 0x55) {
    throw new RepoWriteError('InvalidRequest', `${path}.ref must be a raw CIDv1 blob CID`);
  }
  if (cid.multihash.code !== 0x12 || cid.multihash.digest.byteLength !== 32) {
    throw new RepoWriteError('InvalidRequest', `${path}.ref must use a SHA-256 multihash`);
  }
}

function isLegacyBlobObject(obj: Record<string, unknown>): boolean {
  const keys = Object.keys(obj).sort();
  return keys.join('\0') === ['cid', 'mimeType'].join('\0') &&
    typeof obj.cid === 'string' &&
    typeof obj.mimeType === 'string';
}

function validateLegacyBlobObject(obj: Record<string, unknown>, path: string): void {
  let cid;
  try {
    cid = CID.parse(String(obj.cid));
  } catch {
    throw new RepoWriteError('InvalidRequest', `${path}.cid must contain a valid CID`);
  }
  validateRawBlobCid(cid, path);
  if (typeof obj.mimeType !== 'string' || obj.mimeType.length === 0) {
    throw new RepoWriteError('InvalidRequest', `${path}.mimeType must be non-empty`);
  }
}

function validateDataCid(cid: CID, path: string): void {
  if (cid.version !== 1) {
    throw new RepoWriteError('InvalidRequest', `${path} must contain a CIDv1 link`);
  }
  if (cid.code !== 0x71 && cid.code !== 0x55) {
    throw new RepoWriteError('InvalidRequest', `${path} must use dag-cbor or raw multicodec`);
  }
  if (cid.multihash.code !== 0x12 || cid.multihash.digest.byteLength !== 32) {
    throw new RepoWriteError('InvalidRequest', `${path} must use a SHA-256 multihash`);
  }
}

function isSimpleBase64(value: string): boolean {
  if (value === '') return true;
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(value)) return false;
  const padding = value.endsWith('==') ? 2 : value.endsWith('=') ? 1 : 0;
  const bodyLength = value.length - padding;
  if (bodyLength === 0) return false;
  if (padding > 0 && value.length % 4 !== 0) return false;
  if (padding === 1) return bodyLength % 4 === 3;
  if (padding === 2) return bodyLength % 4 === 2;
  return bodyLength % 4 !== 1;
}

async function validateBlobRefs(
  env: Env,
  did: string,
  record: Record<string, unknown>,
): Promise<string[]> {
  const blobs: Array<{ cid: string; mimeType: string; size: number }> = [];
  collectBlobRefs(record, blobs);
  const keys = new Set<string>();
  for (const blob of blobs) {
    const row = await env.ALTERAN_DB.prepare(
      'SELECT key, mime, size FROM blob WHERE did = ? AND cid = ? LIMIT 1',
    ).bind(did, blob.cid).first<{ key: string; mime: string; size: number }>();
    if (!row) {
      throw new RepoWriteError('BlobNotFound', `blob not found: ${blob.cid}`);
    }
    if (row.mime !== blob.mimeType) {
      throw new RepoWriteError('InvalidMimeType', `blob mime type mismatch: ${blob.cid}`);
    }
    if (Number(row.size) !== blob.size) {
      throw new RepoWriteError('InvalidSize', `blob size mismatch: ${blob.cid}`);
    }
    const object = typeof (env.ALTERAN_BLOBS as any).head === 'function'
      ? await (env.ALTERAN_BLOBS as any).head(row.key)
      : await env.ALTERAN_BLOBS.get(row.key);
    if (!object) {
      throw new RepoWriteError('BlobNotFound', `blob not found: ${blob.cid}`);
    }
    keys.add(row.key);
  }
  return Array.from(keys);
}

function collectBlobRefs(value: unknown, refs: Array<{ cid: string; mimeType: string; size: number }>): void {
  if (!value || typeof value !== 'object') return;
  if (Array.isArray(value)) {
    for (const item of value) collectBlobRefs(item, refs);
    return;
  }
  const obj = value as Record<string, unknown>;
  if (obj.$type === 'blob') {
    const blob = validateBlobObject(obj, 'blob');
    refs.push({ cid: blob.cid.toString(), mimeType: blob.mimeType, size: blob.size });
    return;
  }
  for (const child of Object.values(obj)) collectBlobRefs(child, refs);
}

function checkSwapCommit(value: unknown, currentCommitCid: string | null): void {
  if (value === undefined) return;
  if (typeof value !== 'string') throw new RepoWriteError('InvalidRequest', 'swapCommit must be a CID');
  if (value !== currentCommitCid) throw new RepoWriteError('InvalidSwap', 'swapCommit mismatch');
}

function expectedCommitCidForRequest(
  body: Record<string, unknown>,
  currentCommitCid: string | null,
): string | null | undefined {
  if (hasSwapCommit(body)) checkSwapCommit(body.swapCommit, currentCommitCid);
  return currentCommitCid;
}

function isRepoCommitConflict(error: unknown): boolean {
  return error instanceof Error && error.name === 'RepoCommitConflictError';
}

function isRepoBlobNotFound(error: unknown): boolean {
  return error instanceof Error && error.name === 'RepoBlobNotFoundError';
}

function checkSwapRecord(value: unknown, currentCid: CID | null, nullable: boolean): void {
  if (value === undefined) return;
  if (value === null && nullable) {
    if (currentCid) throw new RepoWriteError('InvalidSwap', 'swapRecord mismatch');
    return;
  }
  if (typeof value !== 'string') throw new RepoWriteError('InvalidRequest', 'swapRecord must be a CID');
  if (!currentCid || value !== currentCid.toString()) {
    throw new RepoWriteError('InvalidSwap', 'swapRecord mismatch');
  }
}

async function getCurrentCommitCid(env: Env, did: string): Promise<string | null> {
  const row = await env.ALTERAN_DB.prepare(
    'SELECT commit_cid AS commitCid FROM repo_root WHERE did = ? LIMIT 1',
  ).bind(did).first<{ commitCid: string }>();
  return row?.commitCid ?? null;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}
