import { CID } from "multiformats/cid";
import * as dagCbor from "@ipld/dag-cbor";
import { cidForCbor } from "../../lib/mst/util";
import type { BlockMap, MST } from "../../lib/mst";
import { RepoWriteError } from "../../lib/repo-write-error";
import { decodeLexBytes } from "../../lib/lex-bytes";

export type EncodedBlock = readonly [CID, Uint8Array];

export function recordToIpld(record: unknown, depth = 0): unknown {
  if (depth > 100) {
    throw new RepoWriteError("InvalidRequest", "record is too deeply nested");
  }
  if (Array.isArray(record)) {
    return record.map((item) => recordToIpld(item, depth + 1));
  }
  if (!record || typeof record !== "object") {
    return record;
  }
  if (record instanceof Uint8Array || CID.asCID(record)) {
    return record;
  }

  const obj = record as Record<string, unknown>;
  const keys = Object.keys(obj);
  if (keys.length === 1 && typeof obj.$link === "string") {
    return CID.parse(obj.$link);
  }
  if (keys.length === 1 && typeof obj.$bytes === "string") {
    return decodeLexBytes(obj.$bytes);
  }

  const converted: Record<string, unknown> = Object.create(null);
  for (const [key, value] of Object.entries(obj)) {
    if (key === "__proto__") {
      throw new RepoWriteError(
        "InvalidRequest",
        "record contains a forbidden object key",
      );
    }
    converted[key] = recordToIpld(value, depth + 1);
  }
  return converted;
}

export async function cidForRecord(record: unknown): Promise<CID> {
  try {
    return cidForCbor(recordToIpld(record));
  } catch (error) {
    if (error instanceof RepoWriteError) throw error;
    throw new RepoWriteError(
      "InvalidRequest",
      "record is not dag-cbor encodable",
    );
  }
}

export async function encodeRecordBlock(
  record: unknown,
): Promise<EncodedBlock> {
  try {
    const ipldRecord = recordToIpld(record);
    const bytes = dagCbor.encode(ipldRecord);
    const cid = await cidForCbor(ipldRecord);
    return [cid, bytes] as const;
  } catch (error) {
    if (error instanceof RepoWriteError) throw error;
    throw new RepoWriteError(
      "InvalidRequest",
      "record is not dag-cbor encodable",
    );
  }
}

export async function collectUnstoredMstBlocks(
  mst: MST,
): Promise<BlockMap> {
  const diff = await mst.getUnstoredBlocks();
  return diff.blocks;
}
