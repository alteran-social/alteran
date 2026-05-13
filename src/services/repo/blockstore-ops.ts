import { CID } from 'multiformats/cid';
import * as dagCbor from '@ipld/dag-cbor';
import { fromString as bytesFromString } from 'uint8arrays/from-string';
import { cidForCbor } from '../../lib/mst/util';
import type { D1Blockstore, MST, BlockMap } from '../../lib/mst';

export function recordToIpld(record: unknown): unknown {
  if (Array.isArray(record)) {
    return record.map((item) => recordToIpld(item));
  }
  if (!record || typeof record !== 'object') {
    return record;
  }
  if (record instanceof Uint8Array || CID.asCID(record)) {
    return record;
  }

  const obj = record as Record<string, unknown>;
  const keys = Object.keys(obj);
  if (keys.length === 1 && typeof obj.$link === 'string') {
    return CID.parse(obj.$link);
  }
  if (keys.length === 1 && typeof obj.$bytes === 'string') {
    return bytesFromString(obj.$bytes, 'base64');
  }

  const converted: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj)) {
    converted[key] = recordToIpld(value);
  }
  return converted;
}

export async function cidForRecord(record: unknown): Promise<CID> {
  return cidForCbor(recordToIpld(record));
}

export async function storeRecord(
  blockstore: D1Blockstore,
  record: unknown,
): Promise<CID> {
  const ipldRecord = recordToIpld(record);
  const bytes = dagCbor.encode(ipldRecord);
  const cid = await cidForCbor(ipldRecord);
  await blockstore.put(cid, bytes);
  return cid;
}

export async function storeMstBlocks(
  blockstore: D1Blockstore,
  mst: MST,
): Promise<BlockMap> {
  const diff = await mst.getUnstoredBlocks();
  for (const [cid, bytes] of diff.blocks) {
    console.log(
      `[RepoManager] Storing new MST block: ${cid.toString()}, size: ${bytes.length}`,
    );
    await blockstore.put(cid, bytes);
  }
  console.log(`[RepoManager] Stored ${diff.blocks.size} new MST blocks`);
  return diff.blocks;
}
