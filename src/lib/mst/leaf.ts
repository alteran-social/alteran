import type { CID } from 'multiformats/cid';
import type { MST } from './mst';
import type { NodeEntry } from './types';

export class Leaf {
  constructor(
    public key: string,
    public value: CID,
  ) {}

  isTree(): this is MST {
    return false;
  }

  isLeaf(): this is Leaf {
    return true;
  }

  equals(entry: NodeEntry): boolean {
    if (entry.isLeaf()) {
      return this.key === entry.key && this.value.equals(entry.value);
    }
    return false;
  }
}
