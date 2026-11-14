import type { Keypair } from "@atproto/crypto-spaces";
import {
  BlockMap,
  blocksToCarFile,
  getRecords,
  MemoryBlockstore,
  type RecordCreateOp,
  Repo,
  signCommit,
  WriteOpAction,
} from "@atproto/repo";
import type { CID } from "multiformats/cid";

export const DID = "did:plc:ztamizklsl7koph5mbiuuuc4";
export const NSID = "com.example.forum";
export const COLLECTION = "com.atproto.lexicon.schema";
const REV = "3n2a5tw2wd22l";
export const target = `${COLLECTION}/${NSID}`;
const utf8 = new TextEncoder();

export function schema(id = NSID) {
  return {
    $type: COLLECTION,
    lexicon: 1,
    id,
    defs: {
      main: { type: "space", key: "any", collections: ["com.example.note"] },
    },
  };
}

export async function collect(
  stream: AsyncIterable<Uint8Array>,
): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  let size = 0;
  for await (const chunk of stream) {
    chunks.push(chunk);
    size += chunk.length;
  }
  const out = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

export async function validFixture(key: Keypair, count = 8) {
  const storage = new MemoryBlockstore();
  const writes: RecordCreateOp[] = [
    {
      action: WriteOpAction.Create,
      collection: COLLECTION,
      rkey: NSID,
      record: schema(),
    },
    ...Array.from({ length: count }, (_, i) => ({
      action: WriteOpAction.Create as const,
      collection: "com.example.other" as const,
      rkey: `record${i}`,
      record: { $type: "com.example.other", text: `record ${i}` },
    })),
  ];
  const repo = await Repo.create(storage, DID, key, writes);
  const proof = await collect(
    getRecords(storage, repo.cid, [{ collection: COLLECTION, rkey: NSID }]),
  );
  return {
    nsid: NSID,
    publisherDid: DID,
    signingKey: key.did(),
    currentCommitCid: repo.cid.toString(),
    proof,
  };
}

export async function signedTree(
  key: Keypair,
  build: (blocks: BlockMap, recordCid: CID) => Promise<CID>,
) {
  const blocks = new BlockMap();
  const recordCid = await blocks.add(schema());
  const nodeCid = await build(blocks, recordCid as unknown as CID);
  const commit = await signCommit({
    did: DID,
    version: 3,
    rev: REV,
    prev: null,
    data: nodeCid,
  }, key);
  const root = await blocks.add(commit);
  const proof = await blocksToCarFile(root, blocks);
  return {
    input: {
      nsid: NSID,
      publisherDid: DID,
      signingKey: key.did(),
      currentCommitCid: root.toString(),
      proof,
    },
    blocks,
    commit,
  };
}

export function encodedKey(key: string) {
  return utf8.encode(key);
}

export function compressedKey(previous: string, next: string) {
  let p = 0;
  while (p < previous.length && previous[p] === next[p]) p++;
  return { p, k: encodedKey(next.slice(p)) };
}
