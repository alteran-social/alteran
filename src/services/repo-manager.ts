import { CID } from 'multiformats/cid';
import type { Env } from '../env';
import { MST, D1Blockstore, type BlockMap } from '../lib/mst';
import { drizzle } from 'drizzle-orm/d1';
import { repo_root } from '../db/schema';
import { eq, sql } from 'drizzle-orm';
import type { RepoOp } from '../lib/firehose/frames';
import {
  putRecordStatements,
  setRecordBlobUsageStatements,
  getRecordBlobKeys,
  type BlobKeyRef,
} from '../db/dal';
import { assertRepoHead, bumpRoot } from '../db/repo';
import { generateTid } from '../lib/commit';
import { resolveSecret } from '../lib/secrets';
import { storeRecord, storeMstBlocks, cidForRecord } from './repo/blockstore-ops';
import { extractOps as extractOpsImpl } from './repo/operations';
import { ServerMisconfigured } from '../lib/errors';
import { RepoWriteError } from '../lib/repo-write-error';
import type { PreparedWrite } from '../lib/repo-write-validation';
import { assertBlobKeysAvailable, resolveRecordBlobKeys } from './repo/blob-refs';
import {
  applyPreparedWritesToRepo,
  type BatchCommitResult,
} from './repo/apply-prepared-writes';

interface RecordMutation {
  mst: MST;
  recordCid: CID;
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
    await storeMstBlocks(this.blockstore, mst);
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
    const recordCid = await storeRecord(this.blockstore, record);
    const newMst = await currentMst.add(key, recordCid);
    const newMstBlocks = await storeMstBlocks(this.blockstore, newMst);
    return { mst: newMst, recordCid, prevMstRoot, newMstBlocks };
  }

  async createRecord(
    collection: string,
    record: unknown,
    rkey?: string,
    blobKeys?: string[],
    expectedCommitCid?: string | null,
  ): Promise<CommitResult> {
    const key = rkey ?? generateTid();
    const { mst, recordCid, prevMstRoot, newMstBlocks } = await this.addRecord(
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
        expectedCommitCid,
        requiredBlobKeys: effectiveBlobKeys,
        sideEffectStatements: (guard) => [
          ...putRecordStatements(this.env, {
            uri,
            did,
            cid: recordCid.toString(),
            json: JSON.stringify(record),
          }, guard),
          ...setRecordBlobUsageStatements(this.env, did, uri, effectiveBlobKeys, guard),
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
    const recordCid = await storeRecord(this.blockstore, record);
    const newMst = await currentMst.update(key, recordCid);
    const newMstBlocks = await storeMstBlocks(this.blockstore, newMst);
    return { mst: newMst, recordCid, prevMstRoot, newMstBlocks };
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
    const recordCid = await cidForRecord(record);
    const did = await this.getDid();
    const effectiveBlobKeys = blobKeys ?? await resolveRecordBlobKeys(this.env, did, record);
    const uri = `at://${did}/${collection}/${rkey}`;
    if (existingCid?.toString() === recordCid.toString()) {
      await assertRepoHead(this.env, did, expectedCommitCid);
      return { uri, cid: recordCid.toString(), ops: [] };
    }

    const previousBlobKeys = await getRecordBlobKeys(this.env, did, uri);
    await storeRecord(this.blockstore, record);
    const mst = existingCid
      ? await currentMst.update(key, recordCid)
      : await currentMst.add(key, recordCid);
    const newMstBlocks = await storeMstBlocks(this.blockstore, mst);
    const currentRoot = await mst.getPointer();
    await assertBlobKeysAvailable(this.env, did, effectiveBlobKeys);
    const { commitCid, rev, ops, commitData, sig, blocks } = await bumpRoot(
      this.env,
      prevMstRoot ?? undefined,
      currentRoot,
      {
        newMstBlocks: Array.from(newMstBlocks),
        expectedCommitCid,
        requiredBlobKeys: effectiveBlobKeys,
        sideEffectStatements: (guard) => [
          ...putRecordStatements(this.env, {
            uri,
            did,
            cid: recordCid.toString(),
            json: JSON.stringify(record),
          }, guard),
          ...setRecordBlobUsageStatements(this.env, did, uri, effectiveBlobKeys, guard),
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
    return applyPreparedWritesToRepo(
      this.env,
      this.blockstore,
      did,
      await this.getOrCreateRoot(),
      writes,
      expectedCommitCid,
    );
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
    const newMstBlocks = await storeMstBlocks(this.blockstore, newMst);

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
