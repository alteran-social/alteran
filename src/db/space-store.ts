import { isValidNsid, isValidRecordKey, isValidTid } from '@atproto/syntax-spaces';
import { MAX_RECORD_SIZE } from '@atproto/space';
import type { Env } from '../env';
import { resolveSecret } from '../lib/secrets';
import { parseCanonicalRepoCid } from '../lib/spaces/repo-cid';
import { encodeRecordBlock } from '../services/repo/blockstore-ops';
import { parseSpaceRef } from './space-ref';
import { validSpaceRecordBlock } from './space-record-block';
import { commitSpaceWrites, loadSpaceSnapshot } from './space-mutation';
import { captureSpaceWrites } from './space-write-input';
import { MAX_SPACE_WRITE_BYTES, SpaceStorageError, type PreparedSpaceWrite, type SpaceCommit, type SpaceWrite } from './space-types';

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
  const captured = captureSpaceWrites(writes);
  if (repoDid !== await localDid(env)) throw new SpaceStorageError('RepoNotFound', 'Repo is not local');
  if (captured.length === 0) return null;

  const prepared = await prepareWrites(captured);
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
    if (write.action === 'delete') {
      prepared.push(write);
      continue;
    }
    const [cid, value] = await encodeRecordBlock(write.record);
    bytes += value.byteLength;
    if (bytes > MAX_SPACE_WRITE_BYTES) throw new SpaceStorageError('InvalidRequest', 'Space write batch is too large');
    prepared.push({ action: write.action, collection: write.collection, rkey: write.rkey, cid: cid.toString(), value, blobs: [] });
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
    `SELECT CASE WHEN typeof(record.cid) = 'text' AND length(CAST(record.cid AS BLOB)) <= 128
         THEN record.cid END AS cid,
       CASE WHEN typeof(record.value_cbor) = 'blob' AND length(record.value_cbor) BETWEEN 1 AND ?
         THEN record.value_cbor END AS value_cbor,
       CASE WHEN typeof(record.repo_rev) = 'text' AND length(CAST(record.repo_rev AS BLOB)) = 13
         THEN record.repo_rev END AS repo_rev,
       CASE WHEN typeof(h.rev) = 'text' AND length(CAST(h.rev AS BLOB)) = 13 THEN h.rev END AS head_rev,
       CASE WHEN typeof(record.value_cbor) <> 'blob' THEN 0
         WHEN length(record.value_cbor) NOT BETWEEN 1 AND ? THEN 0
         WHEN v.epoch_id IS NOT NULL AND v.cid IS record.cid AND v.value_cbor IS record.value_cbor
         AND v.repo_rev IS record.repo_rev AND typeof(v.value_size) = 'integer'
         AND v.value_size = length(record.value_cbor) AND typeof(h.generation) = 'integer'
         AND h.generation BETWEEN 1 AND 9007199254740991
         AND typeof(v.from_generation) = 'integer' AND v.from_generation BETWEEN 1 AND h.generation
         THEN 1 ELSE 0 END AS consistent
     FROM space_record record
     JOIN space ON space.space_ref = record.space_ref AND space.deleted_at IS NULL
     JOIN space_repo h ON h.space_ref = record.space_ref AND h.repo_did = record.repo_did
     JOIN space_epoch e ON e.id = h.active_epoch_id AND e.space_ref = h.space_ref
       AND e.repo_did = h.repo_did AND e.state = 'active'
     LEFT JOIN space_record_version v ON v.epoch_id = e.id AND v.space_ref = record.space_ref
       AND v.repo_did = record.repo_did AND v.path = record.collection || '/' || record.rkey
       AND v.until_generation IS NULL
     WHERE record.space_ref = ? AND record.repo_did = ? AND record.collection = ? AND record.rkey = ?`,
  ).bind(MAX_RECORD_SIZE, MAX_RECORD_SIZE, spaceRef, repoDid, collection, rkey)
    .first<{ cid: string | null; value_cbor: number[] | null; repo_rev: string | null;
      head_rev: string | null; consistent: number }>();
  if (!row) return null;
  if (row.consistent !== 1 || !row.cid || parseCanonicalRepoCid(row.cid)?.toString() !== row.cid ||
    !row.repo_rev || !isValidTid(row.repo_rev) || !row.head_rev || !isValidTid(row.head_rev) ||
    row.repo_rev > row.head_rev || !Array.isArray(row.value_cbor) ||
    row.value_cbor.length < 1 || row.value_cbor.length > MAX_RECORD_SIZE ||
    !row.value_cbor.every((byte: unknown) => typeof byte === 'number' && Number.isInteger(byte) && byte >= 0 && byte <= 255)) {
    throw new SpaceStorageError('InvalidRepoState', 'Invalid Space record');
  }
  const value = Uint8Array.from(row.value_cbor);
  if (!validSpaceRecordBlock(collection, row.cid, value)) {
    throw new SpaceStorageError('InvalidRepoState', 'Invalid Space record');
  }
  return { cid: row.cid, value, rev: row.repo_rev };
}

async function localDid(env: Env): Promise<string> {
  const did = await resolveSecret(env.PDS_DID);
  if (!did) throw new SpaceStorageError('ServerMisconfigured', 'PDS_DID is required');
  return did;
}
