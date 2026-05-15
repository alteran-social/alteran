import { CID } from 'multiformats/cid';
import type { Env } from '../env';
import { MST, D1Blockstore, type BlockMap } from '../lib/mst';
import { drizzle } from 'drizzle-orm/d1';
import { repo_root } from '../db/schema';
import { eq, sql } from 'drizzle-orm';
import type { RepoOp } from '../lib/firehose/frames';
import {
  putRecordStatements,
  repairRecordBlobUsageForCurrentRecord,
  setRecordBlobUsageStatements,
  getRecordBlobKeys,
  type BlobKeyRef,
} from '../db/dal';
import { assertRepoHead, bumpRoot, RepoBlobNotFoundError, RepoCommitConflictError } from '../db/repo';
import { generateTid } from '../lib/commit';
import { resolveSecret } from '../lib/secrets';
import {
  collectUnstoredMstBlocks,
  encodeRecordBlock,
  cidForRecord,
  type EncodedBlock,
} from './repo/blockstore-ops';
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
  recordBlock: EncodedBlock;
  prevMstRoot: CID | null;
  expectedCommitCid: string | null;
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

  private async getRootSnapshot(): Promise<{ mst: MST; commitCid: string } | null> {
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

    return { mst: await MST.load(this.blockstore, mstRoot), commitCid: row.commitCid };
  }

  async getRoot(): Promise<MST | null> {
    return (await this.getRootSnapshot())?.mst ?? null;
  }

  private async getOrCreateRootSnapshot(): Promise<{ mst: MST; commitCid: string | null }> {
    const existing = await this.getRootSnapshot();
    if (existing) {
      const pointer = await existing.mst.getPointer();
      console.log(`[RepoManager] Loaded existing MST root: ${pointer.toString()}`);
      return existing;
    }

    console.log('[RepoManager] Creating new empty MST');
    const mst = await MST.create(this.blockstore, []);
    const pointer = await mst.getPointer();
    console.log(`[RepoManager] Created new MST root: ${pointer.toString()}`);
    return { mst, commitCid: null };
  }

  async getOrCreateRoot(): Promise<MST> {
    const snapshot = await this.getOrCreateRootSnapshot();
    return snapshot.mst;
  }

  async addRecord(
    collection: string,
    rkey: string,
    record: unknown,
  ): Promise<RecordMutation> {
    const key = `${collection}/${rkey}`;
    const { mst: currentMst, commitCid: expectedCommitCid } = await this.getOrCreateRootSnapshot();
    const prevMstRoot = expectedCommitCid === null ? null : await currentMst.getPointer();
    const recordBlock = await encodeRecordBlock(record);
    const [recordCid] = recordBlock;
    const newMst = await currentMst.add(key, recordCid);
    const newMstBlocks = await collectUnstoredMstBlocks(newMst);
    return { mst: newMst, recordCid, recordBlock, prevMstRoot, expectedCommitCid, newMstBlocks };
  }

  async createRecord(
    collection: string,
    record: unknown,
    rkey?: string,
    blobKeys?: string[],
    expectedCommitCid?: string | null,
  ): Promise<CommitResult> {
    const key = rkey ?? generateTid();
    const { mst, recordCid, recordBlock, prevMstRoot, expectedCommitCid: rootCommitCid, newMstBlocks } = await this.addRecord(
      collection,
      key,
      record,
    );

    const did = await this.getDid();
    const effectiveBlobKeys = blobKeys ?? await resolveRecordBlobKeys(this.env, did, record);
    const uri = `at://${did}/${collection}/${key}`;

    const currentRoot = await mst.getPointer();
    const commitGuard = expectedCommitCid === undefined ? rootCommitCid : expectedCommitCid;
    const opsForCommit: RepoOp[] = [{ action: 'create', path: `${collection}/${key}`, cid: recordCid }];
    await assertBlobKeysAvailable(this.env, did, effectiveBlobKeys);
    const { commitCid, rev, ops, commitData, sig, blocks } = await bumpRoot(
      this.env,
      prevMstRoot ?? undefined,
      currentRoot,
      {
        ops: opsForCommit,
        newMstBlocks: Array.from(newMstBlocks),
        newRecordBlocks: [recordBlock],
        expectedCommitCid: commitGuard,
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
    const { mst: currentMst, commitCid: expectedCommitCid } = await this.getOrCreateRootSnapshot();
    const prevMstRoot = expectedCommitCid === null ? null : await currentMst.getPointer();
    const recordBlock = await encodeRecordBlock(record);
    const [recordCid] = recordBlock;
    const newMst = await currentMst.update(key, recordCid);
    const newMstBlocks = await collectUnstoredMstBlocks(newMst);
    return { mst: newMst, recordCid, recordBlock, prevMstRoot, expectedCommitCid, newMstBlocks };
  }

  async putRecord(
    collection: string,
    rkey: string,
    record: unknown,
    blobKeys?: string[],
    expectedCommitCid?: string | null,
  ): Promise<RecordWriteResult> {
    const key = `${collection}/${rkey}`;
    const { mst: currentMst, commitCid: rootCommitCid } = await this.getOrCreateRootSnapshot();
    const prevMstRoot = rootCommitCid === null ? null : await currentMst.getPointer();
    const existingCid = await currentMst.get(key);
    const recordCid = await cidForRecord(record);
    const did = await this.getDid();
    const effectiveBlobKeys = blobKeys ?? await resolveRecordBlobKeys(this.env, did, record);
    const uri = `at://${did}/${collection}/${rkey}`;
    const commitGuard = expectedCommitCid === undefined ? rootCommitCid : expectedCommitCid;
    if (existingCid?.toString() === recordCid.toString()) {
      if (typeof commitGuard !== 'string') {
        await assertRepoHead(this.env, did, commitGuard);
      } else {
        const repairResult = await repairRecordBlobUsageForCurrentRecord(
          this.env,
          did,
          uri,
          recordCid.toString(),
          effectiveBlobKeys,
          commitGuard,
        );
        if (repairResult.tag === 'blobNotFound') throw new RepoBlobNotFoundError();
        if (repairResult.tag === 'conflict') throw new RepoCommitConflictError();
      }
      return { uri, cid: recordCid.toString(), ops: [] };
    }

    const previousBlobKeys = await getRecordBlobKeys(this.env, did, uri);
    const recordBlock = await encodeRecordBlock(record);
    const mst = existingCid
      ? await currentMst.update(key, recordCid)
      : await currentMst.add(key, recordCid);
    const newMstBlocks = await collectUnstoredMstBlocks(mst);
    const currentRoot = await mst.getPointer();
    const opsForCommit: RepoOp[] = existingCid
      ? [{ action: 'update', path: key, cid: recordCid, prev: existingCid }]
      : [{ action: 'create', path: key, cid: recordCid }];
    await assertBlobKeysAvailable(this.env, did, effectiveBlobKeys);
    const { commitCid, rev, ops, commitData, sig, blocks } = await bumpRoot(
      this.env,
      prevMstRoot ?? undefined,
      currentRoot,
      {
        ops: opsForCommit,
        newMstBlocks: Array.from(newMstBlocks),
        newRecordBlocks: [recordBlock],
        expectedCommitCid: commitGuard,
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
    const snapshot = await this.getOrCreateRootSnapshot();
    return applyPreparedWritesToRepo(
      this.env,
      did,
      snapshot.mst,
      writes,
      expectedCommitCid === undefined ? snapshot.commitCid : expectedCommitCid,
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
    const newMstBlocks = await collectUnstoredMstBlocks(newMst);

    const did = await this.getDid();
    const uri = `at://${did}/${collection}/${rkey}`;

    return { mst: newMst, prevMstRoot, uri, newMstBlocks, currentCid };
  }

  // MST is canonical; if the key isn't in the MST the record doesn't exist,
  // regardless of any stale rows in the `record` table. See the note above
  // listRecords for context.
  async getRecord(collection: string, rkey: string): Promise<unknown | null> {
    const currentMst = await this.getRoot();
    if (!currentMst) return null;

    const recordCid = await currentMst.get(`${collection}/${rkey}`);
    if (!recordCid) return null;

    return this.blockstore.readObj(recordCid);
  }

  // The MST is the canonical record of repo state. We do NOT fall back to the
  // `record` table when the MST is empty for a collection: a row in `record`
  // whose key is absent from the MST is an orphan, and exposing it would let
  // clients (e.g. the AppView) index URIs that subsequent deleteRecord calls
  // silently no-op on, because deleteRecord's existence check goes through
  // the MST.
  async listRecords(
    collection: string,
    limit = 50,
    cursor?: string,
  ): Promise<{ key: string; cid: CID }[]> {
    const currentMst = await this.getRoot();
    if (!currentMst) return [];

    const prefix = `${collection}/`;
    const leaves = await currentMst.listWithPrefix(prefix, limit);

    return leaves
      .filter((leaf) => !cursor || leaf.key > `${collection}/${cursor}`)
      .map((leaf) => ({
        key: leaf.key.replace(prefix, ''),
        cid: leaf.value,
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
