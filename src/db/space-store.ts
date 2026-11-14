import { isValidNsid, isValidRecordKey } from '@atproto/syntax-spaces';
import { MAX_RECORD_SIZE } from '@atproto/space';
import type { Env } from '../env';
import { resolveSecret } from '../lib/secrets';
import { encodeRecordBlock } from '../services/repo/blockstore-ops';
import { parseSpaceRef } from './space-ref';
import { decodeSpaceRecord, SPACE_RECORD_COLUMNS, SPACE_RECORD_TABLES, type SpaceRecordRow } from './space-record-projection';
import { commitSpaceWrites, loadSpaceSnapshot } from './space-mutation';
import { captureSpaceWrites } from './space-write-input';
import { MAX_SPACE_WRITE_BYTES, SpaceStorageError, type PreparedSpaceWrite, type SpaceCommit, type SpaceWrite } from './space-types';

const MAX_RETRIES = 4;

export async function createLocalSpace(env: Env, spaceRef: string): Promise<void> {
  const ref = parseSpaceRef(spaceRef);
  const did = await localDid(env);
  if (ref.authorityDid !== did) throw new SpaceStorageError('NotAuthorized', 'Space authority is not local');
  let result;
  try {
    result = await env.ALTERAN_DB.prepare(
      `INSERT OR IGNORE INTO space (space_ref, authority_did, space_type, skey, created_at)
       VALUES (?, ?, ?, ?, ?)`,
    ).bind(ref.ref, ref.authorityDid, ref.spaceType, ref.skey, Date.now()).run();
  } catch (error) {
    const existing = await env.ALTERAN_DB.prepare('SELECT 1 AS present FROM space WHERE space_ref = ?')
      .bind(ref.ref).first<{ present: number }>();
    if (existing?.present === 1) throw new SpaceStorageError('SpaceAlreadyExists', 'Space already exists or was deleted');
    throw error;
  }
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
    `SELECT ${SPACE_RECORD_COLUMNS}
     ${SPACE_RECORD_TABLES}
     WHERE record.space_ref = ? AND record.repo_did = ? AND record.collection = ? AND record.rkey = ?`,
  ).bind(MAX_RECORD_SIZE, MAX_RECORD_SIZE, spaceRef, repoDid, collection, rkey)
    .first<SpaceRecordRow>();
  return row ? decodeSpaceRecord(row, collection) : null;
}

async function localDid(env: Env): Promise<string> {
  const did = await resolveSecret(env.PDS_DID);
  if (!did) throw new SpaceStorageError('ServerMisconfigured', 'PDS_DID is required');
  return did;
}
