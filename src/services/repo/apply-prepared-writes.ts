import type { CID } from "multiformats/cid";
import type { Env } from "../../env";
import { bumpRoot } from "../../db/repo";
import {
  type BlobKeyRef,
  deleteRecordStatements,
  getRecordBlobKeys,
  putRecordStatements,
  setRecordBlobUsageStatements,
} from "../../db/dal";
import type { RepoOp } from "../../lib/firehose/frames";
import { RepoWriteError } from "../../lib/repo-write-error";
import type { MST } from "../../lib/mst";
import type { RepositoryRecord } from "../../lib/repo-write-data";
import type {
  PreparedWrite,
  ValidationStatus,
} from "../../lib/repo-write-validation";
import {
  collectUnstoredMstBlocks,
  type EncodedBlock,
  encodeRecordBlock,
} from "./blockstore-ops";
import { assertBlobKeysAvailable } from "./blob-refs";

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

type SideEffect =
  | {
    action: "put";
    uri: string;
    cid: string;
    record: RepositoryRecord;
    blobKeys: string[];
  }
  | { action: "delete"; uri: string };

export async function applyPreparedWritesToRepo(
  env: Env,
  did: string,
  root: MST,
  writes: PreparedWrite[],
  expectedCommitCid?: string | null,
): Promise<BatchCommitResult> {
  let mst = root;
  const prevMstRoot = await mst.getPointer();
  const ops: RepoOp[] = [];
  const sideEffects: SideEffect[] = [];
  const results: BatchCommitResult["results"] = [];
  const recordBlocks: EncodedBlock[] = [];

  for (const write of writes) {
    const path = `${write.collection}/${write.rkey}`;
    const uri = `at://${did}/${path}`;
    if (write.action === "delete") {
      const prev = await mst.get(path);
      if (!prev) {
        throw new RepoWriteError("InvalidRequest", "record does not exist");
      }
      mst = await mst.delete(path);
      ops.push({ action: "delete", path, cid: null, prev });
      sideEffects.push({ action: "delete", uri });
      results.push({ $type: "com.atproto.repo.applyWrites#deleteResult" });
      continue;
    }

    const prev = await mst.get(path);
    if (write.action === "update") {
      if (!prev) {
        throw new RepoWriteError("InvalidRequest", "record does not exist");
      }
      const recordBlock = await encodeRecordBlock(write.record);
      const [recordCid] = recordBlock;
      recordBlocks.push(recordBlock);
      mst = await mst.update(path, recordCid);
      ops.push({ action: "update", path, cid: recordCid, prev });
      addPutEffect(sideEffects, results, uri, recordCid, write);
      continue;
    }

    if (prev) {
      throw new RepoWriteError("InvalidRequest", "record already exists");
    }
    const recordBlock = await encodeRecordBlock(write.record);
    const [recordCid] = recordBlock;
    recordBlocks.push(recordBlock);
    mst = await mst.add(path, recordCid);
    ops.push({ action: "create", path, cid: recordCid });
    addPutEffect(sideEffects, results, uri, recordCid, write);
  }

  const dereferencedBlobKeys = await findDereferencedBlobKeys(
    env,
    did,
    sideEffects,
  );
  const currentRoot = await mst.getPointer();
  const newMstBlocks = await collectUnstoredMstBlocks(mst);
  const requiredBlobKeys = sideEffects.flatMap((effect) =>
    effect.action === "put" ? effect.blobKeys : []
  );
  await assertBlobKeysAvailable(env, did, requiredBlobKeys);

  const { commitCid, rev, commitData, sig, blocks } = await bumpRoot(
    env,
    prevMstRoot ?? undefined,
    currentRoot,
    {
      ops,
      newMstBlocks: Array.from(newMstBlocks),
      newRecordBlocks: recordBlocks,
      expectedCommitCid,
      requiredBlobKeys,
      sideEffectStatements: (guard) =>
        sideEffects.flatMap((effect) => {
          if (effect.action === "delete") {
            return [
              ...deleteRecordStatements(env, effect.uri, guard),
              ...setRecordBlobUsageStatements(env, did, effect.uri, [], guard),
            ];
          }
          return [
            ...putRecordStatements(env, {
              uri: effect.uri,
              did,
              cid: effect.cid,
              json: JSON.stringify(effect.record),
            }, guard),
            ...setRecordBlobUsageStatements(
              env,
              did,
              effect.uri,
              effect.blobKeys,
              guard,
            ),
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

function addPutEffect(
  sideEffects: SideEffect[],
  results: BatchCommitResult["results"],
  uri: string,
  recordCid: CID,
  write: Exclude<PreparedWrite, { action: "delete" }>,
): void {
  const cid = recordCid.toString();
  sideEffects.push({
    action: "put",
    uri,
    cid,
    record: write.record,
    blobKeys: write.blobKeys,
  });
  results.push({
    $type: `com.atproto.repo.applyWrites#${write.action}Result`,
    uri,
    cid,
    validationStatus: write.validationStatus,
  });
}

async function findDereferencedBlobKeys(
  env: Env,
  did: string,
  sideEffects: SideEffect[],
): Promise<string[]> {
  const previousBlobKeysByUri = new Map<string, string[]>();
  const finalBlobKeysByUri = new Map<string, string[]>();
  for (const effect of sideEffects) {
    if (!previousBlobKeysByUri.has(effect.uri)) {
      previousBlobKeysByUri.set(
        effect.uri,
        await getRecordBlobKeys(env, did, effect.uri),
      );
    }
    finalBlobKeysByUri.set(
      effect.uri,
      effect.action === "put" ? effect.blobKeys : [],
    );
  }
  return Array.from(previousBlobKeysByUri).flatMap(([uri, previousKeys]) => {
    const finalKeys = finalBlobKeysByUri.get(uri) ?? [];
    return previousKeys.filter((key) => !finalKeys.includes(key));
  });
}
