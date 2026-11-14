import { isValidNsid, isValidRecordKey } from '@atproto/syntax-spaces';
import type { Env } from '../env';
import { resolveSecret } from '../lib/secrets';
import { collectBlobRefs, validateRawRecord, type BlobReference } from '../lib/repo-write-data';
import { encodeRecordBlock } from '../services/repo/blockstore-ops';
import { parseSpaceRef } from './space-ref';
import { commitSpaceWrites, loadSpaceSnapshot } from './space-mutation';
import { MAX_SPACE_WRITE_BYTES, MAX_SPACE_WRITES, SpaceStorageError, type PreparedSpaceWrite, type SpaceCommit, type SpaceWrite } from './space-types';

const MAX_RETRIES = 4;

export async function createLocalSpace(env: Env, spaceRef: string): Promise<void> {
  const ref = parseSpaceRef(spaceRef);
  const did = await localDid(env);
  if (ref.authorityDid !== did) throw new SpaceStorageError('NotAuthorized', 'Space authority is not local');
  const result = await env.ALTERAN_DB.prepare(
    `INSERT OR IGNORE INTO space (space_ref, authority_did, space_type, skey, created_at)
     VALUES (?, ?, ?, ?, ?)`,
  ).bind(ref.ref, ref.authorityDid, ref.spaceType, ref.skey, Date.now()).run();
  if (result.meta.changes !== 1) {
    throw new SpaceStorageError('SpaceAlreadyExists', 'Space already exists or was deleted');
  }
}

export async function applySpaceWrites(
  env: Env,
  spaceRef: string,
  repoDid: string,
  writes: readonly SpaceWrite[],
): Promise<SpaceCommit | null> {
  const ref = parseSpaceRef(spaceRef);
  if (repoDid !== await localDid(env)) throw new SpaceStorageError('RepoNotFound', 'Repo is not local');
  if (writes.length > MAX_SPACE_WRITES) throw new SpaceStorageError('InvalidRequest', 'Too many writes');
  if (writes.length === 0) return null;

  const prepared = await prepareWrites(writes);
  for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
    const snapshot = await loadSpaceSnapshot(env, ref, repoDid, prepared);
    const result = await commitSpaceWrites(env, ref, repoDid, prepared, snapshot);
    if (result.tag === 'committed') return result.commit;
    if (result.tag === 'missingSpace') throw new SpaceStorageError('SpaceNotFound', 'Space does not exist or is deleted');
  }
  throw new SpaceStorageError('RepoConflict', 'Space repo changed during the write');
}

async function prepareWrites(writes: readonly SpaceWrite[]): Promise<PreparedSpaceWrite[]> {
  const prepared: PreparedSpaceWrite[] = [];
  let bytes = 0;
  for (const write of writes) {
    if (!isValidNsid(write.collection) || !isValidRecordKey(write.rkey)) {
      throw new SpaceStorageError('InvalidRequest', 'Invalid collection or record key');
    }
    if (write.action === 'delete') {
      prepared.push(write);
      continue;
    }
    if (write.action !== 'create' && write.action !== 'update') {
      throw new SpaceStorageError('InvalidRequest', 'Invalid write action');
    }
    const record = validateRawRecord(write.collection, write.record);
    const blobs: BlobReference[] = [];
    collectBlobRefs(record, blobs);
    if (blobs.length) throw new SpaceStorageError('BlobIntegrityUnavailable', 'Space blob storage is unavailable');
    const [cid, value] = await encodeRecordBlock(record);
    bytes += value.byteLength;
    if (bytes > MAX_SPACE_WRITE_BYTES) throw new SpaceStorageError('InvalidRequest', 'Space write batch is too large');
    prepared.push({ ...write, cid: cid.toString(), value, blobs });
  }
  return prepared;
}

export async function getSpaceRecord(
  env: Env,
  spaceRef: string,
  repoDid: string,
  collection: string,
  rkey: string,
): Promise<{ readonly cid: string; readonly value: Uint8Array; readonly rev: string } | null> {
  parseSpaceRef(spaceRef);
  if (repoDid !== await localDid(env)) throw new SpaceStorageError('RepoNotFound', 'Repo is not local');
  if (!isValidNsid(collection) || !isValidRecordKey(rkey)) {
    throw new SpaceStorageError('InvalidRequest', 'Invalid collection or record key');
  }
  const row = await env.ALTERAN_DB.prepare(
    `SELECT record.cid, record.value_cbor, record.repo_rev FROM space_record record
     JOIN space ON space.space_ref = record.space_ref AND space.deleted_at IS NULL
     WHERE record.space_ref = ? AND record.repo_did = ? AND record.collection = ? AND record.rkey = ?`,
  ).bind(spaceRef, repoDid, collection, rkey).first<{ cid: string; value_cbor: number[]; repo_rev: string }>();
  return row ? { cid: row.cid, value: Uint8Array.from(row.value_cbor), rev: row.repo_rev } : null;
}

async function localDid(env: Env): Promise<string> {
  const did = await resolveSecret(env.PDS_DID);
  if (!did) throw new SpaceStorageError('ServerMisconfigured', 'PDS_DID is required');
  return did;
}
