import { CID } from 'multiformats/cid';
import * as dagCbor from '@ipld/dag-cbor';
import type { D1Blockstore, NodeData } from '../../lib/mst';
import type { RepoOp } from '../../lib/firehose/frames';

interface NodeEntry {
  p: number;
  k: Uint8Array;
  v: unknown;
  t?: unknown;
}

interface DecodedNode {
  e?: NodeEntry[];
  l?: unknown;
}

function coerceCid(value: unknown): CID {
  const asCid = (CID as unknown as { asCID?: (v: unknown) => CID | null }).asCID?.(value);
  if (asCid) return asCid;
  return CID.parse(String(value));
}

export async function collectLeavesBatched(
  blockstore: D1Blockstore,
  root: CID,
): Promise<Map<string, CID>> {
  const result = new Map<string, CID>();
  const visited = new Set<string>();
  let toFetch: CID[] = [root];

  // Limit per getMany() request; getMany chunks the IN() list further.
  const batchSize = 200;

  while (toFetch.length > 0) {
    const chunk = toFetch.slice(0, batchSize);
    toFetch = toFetch.slice(batchSize);

    const { blocks, missing } = await blockstore.getMany(chunk);

    if (missing.length > 0) {
      // Fail fast: missing MST nodes mean an incomplete repo, and emitting
      // ops without them would produce a wrong diff.
      const missingStr = missing.map((c) => c.toString()).join(', ');
      throw new Error(
        `[RepoManager] collectLeavesBatched: missing MST nodes: ${missingStr}`,
      );
    }

    for (const [cidStr, bytes] of blocks.entries()) {
      if (visited.has(cidStr)) continue;
      visited.add(cidStr);
      try {
        const node = dagCbor.decode(bytes) as DecodedNode;
        let lastKey = '';
        const entries = Array.isArray(node.e) ? node.e : [];
        for (const entry of entries) {
          const keyStr = new TextDecoder('ascii').decode(entry.k);
          const fullKey = lastKey.slice(0, Number(entry.p)) + keyStr;
          try {
            const parts = fullKey.split('/');
            if (parts.length === 2 && parts[0] && parts[1]) {
              result.set(fullKey, coerceCid(entry.v));
            }
          } catch (decodeError) {
            console.warn('[RepoManager] failed to decode leaf CID:', decodeError);
          }
          lastKey = fullKey;

          if (entry.t) {
            const subtree = coerceCid(entry.t);
            if (!visited.has(subtree.toString())) toFetch.push(subtree);
          }
        }

        if (node.l) {
          const left = coerceCid(node.l);
          if (!visited.has(left.toString())) toFetch.push(left);
        }
      } catch (err) {
        console.warn('[RepoManager] collectLeavesBatched: failed to decode node', cidStr, err);
      }
    }
  }

  return result;
}

export async function extractOps(
  blockstore: D1Blockstore,
  prevRoot: CID | null,
  newRoot: CID,
): Promise<RepoOp[]> {
  const ops: RepoOp[] = [];
  const newMap = await collectLeavesBatched(blockstore, newRoot);
  const prevMap = prevRoot
    ? await collectLeavesBatched(blockstore, prevRoot)
    : new Map<string, CID>();

  for (const [path, cid] of Array.from(newMap.entries())) {
    const prevCid = prevMap.get(path);
    if (!prevCid) {
      ops.push({ action: 'create', path, cid });
    } else if (!prevCid.equals(cid)) {
      ops.push({ action: 'update', path, cid, prev: prevCid });
    }
  }

  for (const [path, prevCid] of Array.from(prevMap.entries())) {
    if (!newMap.has(path)) {
      ops.push({ action: 'delete', path, cid: null, prev: prevCid });
    }
  }

  ops.sort((a, b) => a.path.localeCompare(b.path));
  return ops;
}

// Used by the legacy in-memory diff path (kept for compatibility). The batched
// version above is preferred because it avoids per-node round-trips to D1.
export async function collectLeavesRecursive(
  entries: ReadonlyArray<{ isLeaf(): boolean; key?: string; value?: CID; getEntries?: () => Promise<unknown[]> }>,
  map: Map<string, CID>,
): Promise<void> {
  for (const entry of entries) {
    if (entry.isLeaf() && entry.key && entry.value) {
      map.set(entry.key, entry.value);
    } else if (entry.getEntries) {
      const subEntries = (await entry.getEntries()) as typeof entries;
      await collectLeavesRecursive(subEntries, map);
    }
  }
}
