import { CID } from 'multiformats/cid';
import * as dagCbor from '@ipld/dag-cbor';
import { cidForCbor } from '../../lib/mst/util';
import type { D1Blockstore, MST, BlockMap } from '../../lib/mst';

export async function storeRecord(
  blockstore: D1Blockstore,
  record: unknown,
): Promise<CID> {
  const bytes = dagCbor.encode(record);
  const cid = await cidForCbor(record);
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
