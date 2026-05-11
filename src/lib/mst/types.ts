import type { CID } from 'multiformats/cid';
import type { MST } from './mst';
import type { Leaf } from './leaf';

export interface NodeData {
  l: CID | null;
  e: TreeEntry[];
}

export interface TreeEntry {
  p: number;
  k: Uint8Array;
  v: CID;
  t: CID | null;
}

export type NodeEntry = MST | Leaf;

export interface MstOpts {
  layer: number;
}
