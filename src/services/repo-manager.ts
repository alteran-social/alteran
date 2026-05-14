import { CID } from 'multiformats/cid';
import type { Env } from '../env';
import { MST, D1Blockstore, type BlockMap } from '../lib/mst';
import { drizzle } from 'drizzle-orm/d1';
import { repo_root } from '../db/schema';
import { eq, sql } from 'drizzle-orm';
import type { RepoOp } from '../lib/firehose/frames';
import {
  putRecordStatements,
  deleteRecordStatements,
  setRecordBlobUsageStatements,
  getRecordBlobKeys,
  type BlobKeyRef,
} from '../db/dal';
import { assertRepoHead, bumpRoot } from '../db/repo';
import { generateTid } from '../lib/commit';
import { resolveSecret } from '../lib/secrets';
import { collectMstBlocks, encodeRecordBlock } from './repo/blockstore-ops';
import { extractOps as extractOpsImpl } from './repo/operations';
import { ServerMisconfigured } from '../lib/errors';
import {
  RepoWriteError,
  type PreparedWrite,
  type ValidationStatus,
} from '../lib/repo-write-validation';

interface RecordMutation {
  mst: MST;
  recordCid: CID;
  recordBlock: [CID, Uint8Array];
  prevMstRoot: CID | null;
  newMstBlocks: BlockMap;
}

interface CommitResult {
  uri: string;
  cid: string;
  commitCid: string;
  rev: string;
  ops: RepoOp[];
  commitData: string;
  sig: string;
  blocks: string;
  dereferencedBlobKeys: BlobKeyRef[];
}

interface NoopRecordResult {
  uri: string;
  cid: string;
  ops: RepoOp[];
  dereferencedBlobKeys?: undefined;
  commitCid?: undefined;
  rev?: undefined;
  commitData?: undefined;
  sig?: undefined;
  blocks?: undefined;
}

type RecordWriteResult = CommitResult | NoopRecordResult;

export interface BatchCommitResult {
  commit: {
    cid: string;
    rev: string;
  } | null;
  commitCid?: string;
  rev?: string;
  ops: RepoOp[];
  commitData?: string;
  sig?: string;
  blocks?: string;
  results: Array<{
    $type: string;
    uri?: string;
    cid?: string;
    validationStatus?: ValidationStatus;
  }>;
  dereferencedBlobKeys: BlobKeyRef[];
}

export class RepoManager {
  private blockstore: D1Blockstore;

  constructor(private env: Env) {
    this.blockstore = new D1Blockstore(env);
  }

  private async getDid(): Promise<string> {
    const did = await resolveSecret(this.env.PDS_DID);
    if (!did) throw new ServerMisconfigured('PDS_DID is required');
    return did;
  }

  async getRoot(): Promise<MST | null> {
    const db = drizzle(this.env.ALTERAN_DB);
    const did = await this.getDid();

    const rows = await db
      .select()
      .from(repo_root)
      .where(eq(repo_root.did, did))
      .limit(1);

    const row = rows[0];
    if (!row) return null;

    const commit = await this.env.ALTERAN_DB.prepare(
      `SELECT data FROM commit_log WHERE cid = ? LIMIT 1`,
    )
      .bind(row.commitCid)
      .first();

    if (!commit) {
      throw new Error(`repo root points at missing commit ${row.commitCid}`);
    }

    const parsed = JSON.parse(String(commit.data));
    const mstRoot = CID.parse(String(parsed.data));

    console.log(
      `[RepoManager] Loading MST root: ${mstRoot.toString()} from commit: ${row.commitCid}`,
    );

    return MST.load(this.blockstore, mstRoot);
  }

  async getOrCreateRoot(): Promise<MST> {
    const existing = await this.getRoot();
    if (existing) {
      const pointer = await existing.getPointer();
      console.log(`[RepoManager] Loaded existing MST root: ${pointer.toString()}`);
      return existing;
    }

    console.log('[RepoManager] Creating new empty MST');
    const mst = await MST.create(this.blockstore, []);
    const pointer = await mst.getPointer();
    console.log(`[RepoManager] Created new MST root: ${pointer.toString()}`);
    return mst;
  }

  async addRecord(
    collection: string,
    rkey: string,
    record: unknown,
  ): Promise<RecordMutation> {
    const key = `${collection}/${rkey}`;
    const currentMst = await this.getOrCreateRoot();
    const prevMstRoot = await currentMst.getPointer();
    const { cid: recordCid, bytes: recordBytes } = await encodeRecordBlock(record);
    const newMst = await currentMst.add(key, recordCid);
    const newMstBlocks = await collectMstBlocks(this.blockstore, newMst);
    return {
      mst: newMst,
      recordCid,
      recordBlock: [recordCid, recordBytes],
      prevMstRoot,
      newMstBlocks,
    };
  }

  async createRecord(
    collection: string,
    record: unknown,
    rkey?: string,
    blobKeys?: string[],
    expectedCommitCid?: string | null,
  ): Promise<CommitResult> {
    const key = rkey ?? generateTid();
    const { mst, recordCid, recordBlock, prevMstRoot, newMstBlocks } = await this.addRecord(
      collection,
      key,
      record,
    );

    const did = await this.getDid();
    const effectiveBlobKeys = blobKeys ?? await resolveRecordBlobKeys(this.env, did, record);
    const uri = `at://${did}/${collection}/${key}`;

    const currentRoot = await mst.getPointer();
    await assertBlobKeysAvailable(this.env, did, effectiveBlobKeys);
    const { commitCid, rev, ops, commitData, sig, blocks } = await bumpRoot(
      this.env,
      prevMstRoot ?? undefined,
      currentRoot,
      {
        newMstBlocks: Array.from(newMstBlocks),
        newRecordBlocks: [recordBlock],
        ops: [{ action: 'create', path: `${collection}/${key}`, cid: recordCid }],
        expectedCommitCid,
        requiredBlobKeys: effectiveBlobKeys,
        sideEffectStatements: (guard) => [
          ...putRecordStatements(this.env, {
            uri,
            did,
            cid: recordCid.toString(),
            json: JSON.stringify(record),
          }, guard),
          ...setRecordBlobUsageStatements(this.env, did, uri, effectiveBlobKeys, guard, recordCid.toString()),
        ],
      },
    );

    return {
      uri,
      cid: recordCid.toString(),
      commitCid,
      rev,
      ops,
      commitData,
      sig,
      blocks,
      dereferencedBlobKeys: [],
    };
  }

  async updateRecord(
    collection: string,
    rkey: string,
    record: unknown,
  ): Promise<RecordMutation> {
    const key = `${collection}/${rkey}`;
    const currentMst = await this.getOrCreateRoot();
    const prevMstRoot = await currentMst.getPointer();
    const { cid: recordCid, bytes: recordBytes } = await encodeRecordBlock(record);
    const newMst = await currentMst.update(key, recordCid);
    const newMstBlocks = await collectMstBlocks(this.blockstore, newMst);
    return {
      mst: newMst,
      recordCid,
      recordBlock: [recordCid, recordBytes],
      prevMstRoot,
      newMstBlocks,
    };
  }

  async putRecord(
    collection: string,
    rkey: string,
    record: unknown,
    blobKeys?: string[],
    expectedCommitCid?: string | null,
  ): Promise<RecordWriteResult> {
    const key = `${collection}/${rkey}`;
    const currentMst = await this.getOrCreateRoot();
    const prevMstRoot = await currentMst.getPointer();
    const existingCid = await currentMst.get(key);
    const { cid: recordCid, bytes: recordBytes } = await encodeRecordBlock(record);
    const did = await this.getDid();
    const effectiveBlobKeys = blobKeys ?? await resolveRecordBlobKeys(this.env, did, record);
    const uri = `at://${did}/${collection}/${rkey}`;
    if (existingCid?.toString() === recordCid.toString()) {
      await assertRepoHead(this.env, did, expectedCommitCid);
      return { uri, cid: recordCid.toString(), ops: [] };
    }

    const previousBlobKeys = await getRecordBlobKeys(this.env, did, uri);
    const mst = existingCid
      ? await currentMst.update(key, recordCid)
      : await currentMst.add(key, recordCid);
    const newMstBlocks = await collectMstBlocks(this.blockstore, mst);
    const currentRoot = await mst.getPointer();
    await assertBlobKeysAvailable(this.env, did, effectiveBlobKeys);
    const { commitCid, rev, ops, commitData, sig, blocks } = await bumpRoot(
      this.env,
      prevMstRoot ?? undefined,
      currentRoot,
      {
        newMstBlocks: Array.from(newMstBlocks),
        newRecordBlocks: [[recordCid, recordBytes]],
        ops: [{
          action: existingCid ? 'update' : 'create',
          path: key,
          cid: recordCid,
          ...(existingCid ? { prev: existingCid } : {}),
        }],
        expectedCommitCid,
        requiredBlobKeys: effectiveBlobKeys,
        sideEffectStatements: (guard) => [
          ...putRecordStatements(this.env, {
            uri,
            did,
            cid: recordCid.toString(),
            json: JSON.stringify(record),
          }, guard),
          ...setRecordBlobUsageStatements(this.env, did, uri, effectiveBlobKeys, guard, recordCid.toString()),
        ],
      },
    );
    return {
      uri,
      cid: recordCid.toString(),
      commitCid,
      rev,
      ops,
      commitData,
      sig,
      blocks,
      dereferencedBlobKeys: previousBlobKeys
        .filter((key) => !effectiveBlobKeys.includes(key))
        .map((key) => ({ did, key })),
    };
  }

  async getRecordCid(collection: string, rkey: string): Promise<CID | null> {
    const currentMst = await this.getRoot();
    if (!currentMst) return null;
    return currentMst.get(`${collection}/${rkey}`);
  }

  async applyPreparedWrites(
    writes: PreparedWrite[],
    expectedCommitCid?: string | null,
  ): Promise<BatchCommitResult> {
    const did = await this.getDid();
    let mst = await this.getOrCreateRoot();
    const prevMstRoot = await mst.getPointer();
    const ops: RepoOp[] = [];
    const sideEffects: Array<
      | { action: 'put'; uri: string; cid: string; record: unknown; blobKeys: string[] }
      | { action: 'delete'; uri: string }
    > = [];
    const recordBlocks: Array<[CID, Uint8Array]> = [];
    const results: BatchCommitResult['results'] = [];

    for (const write of writes) {
      const path = `${write.collection}/${write.rkey}`;
      const uri = `at://${did}/${path}`;
      if (write.action === 'delete') {
        const prev = await mst.get(path);
        if (!prev) {
          results.push({ $type: 'com.atproto.repo.applyWrites#deleteResult' });
          continue;
        }
        mst = await mst.delete(path);
        ops.push({ action: 'delete', path, cid: null, prev });
        sideEffects.push({ action: 'delete', uri });
        results.push({ $type: 'com.atproto.repo.applyWrites#deleteResult' });
        continue;
      }

      const prev = await mst.get(path);
      if (write.action === 'update') {
        if (!prev) throw new RepoWriteError('InvalidRequest', 'record does not exist');
        const { cid: recordCid, bytes: recordBytes } = await encodeRecordBlock(write.record);
        recordBlocks.push([recordCid, recordBytes]);
        mst = await mst.update(path, recordCid);
        ops.push({ action: 'update', path, cid: recordCid, prev });
        const cid = recordCid.toString();
        sideEffects.push({
          action: 'put',
          uri,
          cid,
          record: write.record,
          blobKeys: write.blobKeys,
        });
        results.push({
          $type: 'com.atproto.repo.applyWrites#updateResult',
          uri,
          cid,
          validationStatus: write.validationStatus,
        });
        continue;
      }

      if (prev) throw new RepoWriteError('InvalidRequest', 'record already exists');
      const { cid: recordCid, bytes: recordBytes } = await encodeRecordBlock(write.record);
      recordBlocks.push([recordCid, recordBytes]);
      mst = await mst.add(path, recordCid);
      ops.push({ action: 'create', path, cid: recordCid });
      const cid = recordCid.toString();
      sideEffects.push({
        action: 'put',
        uri,
        cid,
        record: write.record,
        blobKeys: write.blobKeys,
      });
      results.push({
        $type: 'com.atproto.repo.applyWrites#createResult',
        uri,
        cid,
        validationStatus: write.validationStatus,
      });
    }

    if (ops.length === 0 && sideEffects.length === 0) {
      await assertRepoHead(this.env, did, expectedCommitCid);
      return {
        commit: null,
        ops,
        results,
        dereferencedBlobKeys: [],
      };
    }

    const previousBlobKeysByUri = new Map<string, string[]>();
    const finalBlobKeysByUri = new Map<string, string[]>();
    for (const effect of sideEffects) {
      if (!previousBlobKeysByUri.has(effect.uri)) {
        previousBlobKeysByUri.set(
          effect.uri,
          await getRecordBlobKeys(this.env, did, effect.uri),
        );
      }
      finalBlobKeysByUri.set(
        effect.uri,
        effect.action === 'put' ? effect.blobKeys : [],
      );
    }
    const dereferencedBlobKeys = Array.from(previousBlobKeysByUri).flatMap(
      ([uri, previousKeys]) => {
        const finalKeys = finalBlobKeysByUri.get(uri) ?? [];
        return previousKeys.filter((key) => !finalKeys.includes(key));
      },
    );

    const currentRoot = await mst.getPointer();
    const newMstBlocks = await collectMstBlocks(this.blockstore, mst);
    await assertBlobKeysAvailable(
      this.env,
      did,
      sideEffects.flatMap((effect) => effect.action === 'put' ? effect.blobKeys : []),
    );
    const { commitCid, rev, commitData, sig, blocks } = await bumpRoot(
      this.env,
      prevMstRoot ?? undefined,
      currentRoot,
      {
        ops,
        newMstBlocks: Array.from(newMstBlocks),
        newRecordBlocks: recordBlocks,
        expectedCommitCid,
        requiredBlobKeys: sideEffects.flatMap((effect) =>
          effect.action === 'put' ? effect.blobKeys : [],
        ),
        sideEffectStatements: (guard) => sideEffects.flatMap((effect) => {
          if (effect.action === 'delete') {
            return [
              ...deleteRecordStatements(this.env, effect.uri, guard),
              ...setRecordBlobUsageStatements(this.env, did, effect.uri, [], guard),
            ];
          }
          return [
            ...putRecordStatements(this.env, {
              uri: effect.uri,
              did,
              cid: effect.cid,
              json: JSON.stringify(effect.record),
            }, guard),
              ...setRecordBlobUsageStatements(this.env, did, effect.uri, effect.blobKeys, guard, effect.cid),
          ];
        }),
      },
    );

    return {
      commit: { cid: commitCid, rev },
      commitCid,
      rev,
      ops,
      commitData,
      sig,
      blocks,
      results,
      dereferencedBlobKeys: dereferencedBlobKeys.map((key) => ({ did, key })),
    };
  }

  async deleteRecord(
    collection: string,
    rkey: string,
  ): Promise<{ mst: MST; prevMstRoot: CID | null; uri: string; newMstBlocks: BlockMap; currentCid: CID }> {
    const key = `${collection}/${rkey}`;
    const currentMst = await this.getOrCreateRoot();
    const prevMstRoot = await currentMst.getPointer();
    const currentCid = await currentMst.get(key);
    if (!currentCid) throw new RepoWriteError('InvalidRequest', 'record does not exist');
    const newMst = await currentMst.delete(key);
    const newMstBlocks = await collectMstBlocks(this.blockstore, newMst);

    const did = await this.getDid();
    const uri = `at://${did}/${collection}/${rkey}`;

    return { mst: newMst, prevMstRoot, uri, newMstBlocks, currentCid };
  }

  async getRecord(collection: string, rkey: string): Promise<unknown | null> {
    const key = `${collection}/${rkey}`;
    const currentMst = await this.getRoot();
    if (!currentMst) return this.getRecordFromTable(collection, rkey);

    const recordCid = await currentMst.get(key);
    if (!recordCid) return this.getRecordFromTable(collection, rkey);

    return this.blockstore.readObj(recordCid);
  }

  private async getRecordFromTable(collection: string, rkey: string): Promise<unknown | null> {
    const did = await this.getDid();
    const uri = `at://${did}/${collection}/${rkey}`;

    const result = await this.env.ALTERAN_DB.prepare(`SELECT json FROM record WHERE uri = ?`)
      .bind(uri)
      .first();

    if (!result) return null;
    try {
      return JSON.parse(result.json as string);
    } catch (parseError) {
      console.warn('[RepoManager] Failed to parse record JSON:', parseError);
      return null;
    }
  }

  async listRecords(
    collection: string,
    limit = 50,
    cursor?: string,
  ): Promise<{ key: string; cid: CID }[]> {
    const currentMst = await this.getRoot();
    if (!currentMst) return this.listRecordsFromTable(collection, limit, cursor);

    const prefix = `${collection}/`;
    const leaves = await currentMst.listWithPrefix(prefix, limit);

    const results = leaves
      .filter((leaf) => !cursor || leaf.key > `${collection}/${cursor}`)
      .map((leaf) => ({
        key: leaf.key.replace(prefix, ''),
        cid: leaf.value,
      }));

    if (results.length === 0) return this.listRecordsFromTable(collection, limit, cursor);
    return results;
  }

  private async listRecordsFromTable(
    collection: string,
    limit = 50,
    cursor?: string,
  ): Promise<{ key: string; cid: CID }[]> {
    const did = await this.getDid();
    const prefix = `at://${did}/${collection}/`;

    // D1's LIKE planner is flaky on long prefixes; use a >= / < range instead.
    // URIs sort lexicographically so this scans only the collection's slice.
    const rangeEnd =
      prefix.slice(0, -1) +
      String.fromCharCode(prefix.charCodeAt(prefix.length - 1) + 1);

    const stmt = cursor
      ? this.env.ALTERAN_DB.prepare(
          `SELECT uri, cid FROM record WHERE uri >= ? AND uri < ? AND uri > ? ORDER BY uri LIMIT ?`,
        ).bind(prefix, rangeEnd, prefix + cursor, limit)
      : this.env.ALTERAN_DB.prepare(
          `SELECT uri, cid FROM record WHERE uri >= ? AND uri < ? ORDER BY uri LIMIT ?`,
        ).bind(prefix, rangeEnd, limit);

    const result = await stmt.all();
    const rows = result.results as Array<{ uri: string; cid: string }>;

    return rows.map((row) => ({
      key: row.uri.replace(prefix, ''),
      cid: CID.parse(row.cid),
    }));
  }

  async updateRoot(mst: MST, rev: number): Promise<void> {
    const db = drizzle(this.env.ALTERAN_DB);
    const rootCid = await mst.getPointer();
    const did = await this.getDid();
    const revStr = String(rev);

    await db
      .insert(repo_root)
      .values({ did, commitCid: rootCid.toString(), rev: revStr })
      .onConflictDoUpdate({
        target: repo_root.did,
        set: {
          commitCid: sql.raw('excluded.commit_cid'),
          rev: sql.raw('excluded.rev'),
        },
      })
      .run();
  }

  extractOps(prevRoot: CID | null, newRoot: CID): Promise<RepoOp[]> {
    return extractOpsImpl(this.blockstore, prevRoot, newRoot);
  }
}

async function assertBlobKeysAvailable(env: Env, did: string, keys: string[]): Promise<void> {
  for (const key of new Set(keys)) {
    const row = await env.ALTERAN_DB.prepare(
      `SELECT b.cid
       FROM blob b
       WHERE b.did = ?
         AND b.key = ?
         AND b.takedown_ref IS NULL
         AND (
           b.state = 'temp'
           OR (
             b.state = 'permanent'
             AND EXISTS (
               SELECT 1 FROM blob_usage u
               WHERE u.did = b.did AND u.key = b.key
             )
           )
         )
       LIMIT 1`,
    )
      .bind(did, key)
      .first<{ cid: string }>();
    if (!row) {
      throw new RepoWriteError('BlobNotFound', 'blob not found');
    }
    const object = typeof (env.ALTERAN_BLOBS as any).head === 'function'
      ? await (env.ALTERAN_BLOBS as any).head(key)
      : await env.ALTERAN_BLOBS.get(key);
    if (!object) {
      throw new RepoWriteError('BlobNotFound', `blob not found: ${row.cid}`);
    }
  }
}

async function resolveRecordBlobKeys(env: Env, did: string, record: unknown): Promise<string[]> {
  const refs: Array<{ cid: string; mimeType: string; size: number }> = [];
  collectBlobRefs(record, refs);
  const keys = new Set<string>();
  for (const ref of refs) {
    const row = await env.ALTERAN_DB.prepare(
      `SELECT b.key, b.mime, b.size
       FROM blob b
       WHERE b.did = ?
         AND b.cid = ?
         AND b.takedown_ref IS NULL
         AND (
           b.state = 'temp'
           OR (
             b.state = 'permanent'
             AND EXISTS (
               SELECT 1 FROM blob_usage u
               WHERE u.did = b.did AND u.key = b.key
             )
           )
         )
       LIMIT 1`,
    )
      .bind(did, ref.cid)
      .first<{ key: string; mime: string; size: number }>();
    if (!row) {
      throw new RepoWriteError('BlobNotFound', `blob not found: ${ref.cid}`);
    }
    if (row.mime !== ref.mimeType) {
      throw new RepoWriteError('InvalidMimeType', `blob mime type mismatch: ${ref.cid}`);
    }
    if (Number(row.size) !== ref.size) {
      throw new RepoWriteError('InvalidSize', `blob size mismatch: ${ref.cid}`);
    }
    const object = typeof (env.ALTERAN_BLOBS as any).head === 'function'
      ? await (env.ALTERAN_BLOBS as any).head(row.key)
      : await env.ALTERAN_BLOBS.get(row.key);
    if (!object) {
      throw new RepoWriteError('BlobNotFound', `blob not found: ${ref.cid}`);
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
    const ref = obj.ref;
    const cid = ref && typeof ref === 'object'
      ? (ref as Record<string, unknown>).$link
      : obj.cid;
    if (typeof cid === 'string' && typeof obj.mimeType === 'string' && typeof obj.size === 'number') {
      CID.parse(cid);
      refs.push({ cid, mimeType: obj.mimeType, size: obj.size });
    }
    return;
  }
  for (const child of Object.values(obj)) collectBlobRefs(child, refs);
}
