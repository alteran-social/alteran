import * as uint8arrays from 'uint8arrays';
import type { ReadableBlockstore } from './blockstore';
import * as util from './util';
import { Leaf } from './leaf';
import type { NodeData, NodeEntry, MstOpts } from './types';

export async function layerForEntries(entries: NodeEntry[]): Promise<number | null> {
  const firstLeaf = entries.find((entry) => entry.isLeaf());
  if (!firstLeaf || firstLeaf.isTree()) return null;
  return util.leadingZerosOnHash(firstLeaf.key);
}

export async function deserializeNodeData(
  storage: ReadableBlockstore,
  data: NodeData,
  opts?: Partial<MstOpts>,
): Promise<NodeEntry[]> {
  const { MST } = await import('./mst');
  const { layer } = opts || {};
  const entries: NodeEntry[] = [];

  if (data.l !== null) {
    entries.push(MST.load(storage, data.l, { layer: layer ? layer - 1 : undefined }));
  }

  let lastKey = '';
  for (const entry of data.e) {
    const keyStr = uint8arrays.toString(entry.k, 'ascii');
    const key = lastKey.slice(0, entry.p) + keyStr;
    util.ensureValidMstKey(key);
    entries.push(new Leaf(key, entry.v));
    lastKey = key;

    if (entry.t !== null) {
      entries.push(MST.load(storage, entry.t, { layer: layer ? layer - 1 : undefined }));
    }
  }

  return entries;
}

export function serializeNodeData(entries: NodeEntry[]): NodeData {
  const data: NodeData = { l: null, e: [] };
  let i = 0;

  if (entries[0]?.isTree()) {
    i++;
    data.l = entries[0].pointer;
  }

  let lastKey = '';
  while (i < entries.length) {
    const leaf = entries[i];
    const next = entries[i + 1];

    if (!leaf.isLeaf()) {
      throw new Error('Not a valid node: two subtrees next to each other');
    }
    i++;

    let subtree: import('multiformats/cid').CID | null = null;
    if (next?.isTree()) {
      subtree = next.pointer;
      i++;
    }

    util.ensureValidMstKey(leaf.key);
    const prefixLen = util.countPrefixLen(lastKey, leaf.key);
    data.e.push({
      p: prefixLen,
      k: uint8arrays.fromString(leaf.key.slice(prefixLen), 'ascii'),
      v: leaf.value,
      t: subtree,
    });

    lastKey = leaf.key;
  }

  return data;
}

export async function cidForEntries(entries: NodeEntry[]): Promise<import('multiformats/cid').CID> {
  const data = serializeNodeData(entries);
  return util.cidForCbor(data);
}
