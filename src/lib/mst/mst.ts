import { CID } from 'multiformats/cid';
import * as dagCbor from '@ipld/dag-cbor';
import type { ReadableBlockstore } from './blockstore';
import * as util from './util';
import { BlockMap } from './block-map';
import { Leaf } from './leaf';
import type { NodeData, NodeEntry, MstOpts } from './types';
import {
  cidForEntries,
  deserializeNodeData,
  layerForEntries,
  serializeNodeData,
} from './serialize';

export type { NodeData, TreeEntry, NodeEntry, MstOpts } from './types';
export { Leaf } from './leaf';

/**
 * Merkle Search Tree (MST) Implementation
 *
 * Ordered, insert-order-independent, deterministic tree. Keys are laid out
 * alphabetically; each key's layer is determined by leading zeros on its hash
 * (~4 fanout, 2 bits per layer).
 */
export class MST {
  storage: ReadableBlockstore;
  entries: NodeEntry[] | null;
  layer: number | null;
  pointer: CID;
  outdatedPointer = false;

  constructor(
    storage: ReadableBlockstore,
    pointer: CID,
    entries: NodeEntry[] | null,
    layer: number | null,
  ) {
    this.storage = storage;
    this.entries = entries;
    this.layer = layer;
    this.pointer = pointer;
  }

  static async create(
    storage: ReadableBlockstore,
    entries: NodeEntry[] = [],
    opts?: Partial<MstOpts>,
  ): Promise<MST> {
    const pointer = await cidForEntries(entries);
    const { layer = null } = opts || {};
    return new MST(storage, pointer, entries, layer);
  }

  static async fromData(
    storage: ReadableBlockstore,
    data: NodeData,
    opts?: Partial<MstOpts>,
  ): Promise<MST> {
    const { layer = null } = opts || {};
    const entries = await deserializeNodeData(storage, data, opts);
    const pointer = await util.cidForCbor(data);
    return new MST(storage, pointer, entries, layer);
  }

  static load(
    storage: ReadableBlockstore,
    cid: CID,
    opts?: Partial<MstOpts>,
  ): MST {
    const { layer = null } = opts || {};
    return new MST(storage, cid, null, layer);
  }

  async newTree(entries: NodeEntry[]): Promise<MST> {
    const mst = new MST(this.storage, this.pointer, entries, this.layer);
    mst.outdatedPointer = true;
    return mst;
  }

  async getEntries(): Promise<NodeEntry[]> {
    if (this.entries) return [...this.entries];

    if (this.pointer) {
      const data = await this.storage.readObj<NodeData>(this.pointer);
      const firstLeaf = data.e[0];
      const layer = firstLeaf !== undefined
        ? await util.leadingZerosOnHash(firstLeaf.k)
        : undefined;
      this.entries = await deserializeNodeData(this.storage, data, { layer });
      return this.entries;
    }

    throw new Error('No entries or CID provided');
  }

  async getPointer(): Promise<CID> {
    if (!this.outdatedPointer) return this.pointer;
    const { cid } = await this.serialize();
    this.pointer = cid;
    this.outdatedPointer = false;
    return this.pointer;
  }

  async serialize(): Promise<{ cid: CID; bytes: Uint8Array }> {
    let entries = await this.getEntries();

    const outdated = entries.filter((e) => e.isTree() && e.outdatedPointer) as MST[];
    if (outdated.length > 0) {
      await Promise.all(outdated.map((e) => e.getPointer()));
      entries = await this.getEntries();
    }

    const data = serializeNodeData(entries);
    const bytes = dagCbor.encode(data);
    const cid = await util.cidForCbor(data);
    return { cid, bytes };
  }

  async getLayer(): Promise<number> {
    this.layer = await this.attemptGetLayer();
    if (this.layer === null) this.layer = 0;
    return this.layer;
  }

  async attemptGetLayer(): Promise<number | null> {
    if (this.layer !== null) return this.layer;

    const entries = await this.getEntries();
    let layer = await layerForEntries(entries);

    if (layer === null) {
      for (const entry of entries) {
        if (entry.isTree()) {
          const childLayer = await entry.attemptGetLayer();
          if (childLayer !== null) {
            layer = childLayer + 1;
            break;
          }
        }
      }
    }

    if (layer !== null) this.layer = layer;
    return layer;
  }

  // Returns the set of blocks reachable from this node that aren't yet
  // persisted in storage. Used to compute the minimal write set per commit.
  async getUnstoredBlocks(): Promise<{ root: CID; blocks: BlockMap }> {
    const blocks = new BlockMap();
    const pointer = await this.getPointer();

    if (await this.storage.has(pointer)) {
      return { root: pointer, blocks };
    }

    const entries = await this.getEntries();
    const data = serializeNodeData(entries);
    await blocks.add(data);

    for (const entry of entries) {
      if (entry.isTree()) {
        const subtree = await entry.getUnstoredBlocks();
        blocks.addMap(subtree.blocks);
      }
    }

    return { root: pointer, blocks };
  }

  async add(key: string, value: CID, knownZeros?: number): Promise<MST> {
    util.ensureValidMstKey(key);
    const keyZeros = knownZeros ?? (await util.leadingZerosOnHash(key));
    const layer = await this.getLayer();
    const newLeaf = new Leaf(key, value);

    if (keyZeros === layer) {
      const index = await this.findGtOrEqualLeafIndex(key);
      const found = await this.atIndex(index);

      if (found?.isLeaf() && found.key === key) {
        throw new Error(`There is already a value at key: ${key}`);
      }

      const prevNode = await this.atIndex(index - 1);
      if (!prevNode || prevNode.isLeaf()) {
        return this.spliceIn(newLeaf, index);
      }
      const splitSubTree = await prevNode.splitAround(key);
      return this.replaceWithSplit(index - 1, splitSubTree[0], newLeaf, splitSubTree[1]);
    }

    if (keyZeros < layer) {
      const index = await this.findGtOrEqualLeafIndex(key);
      const prevNode = await this.atIndex(index - 1);

      if (prevNode && prevNode.isTree()) {
        const newSubtree = await prevNode.add(key, value, keyZeros);
        return this.updateEntry(index - 1, newSubtree);
      }
      const subTree = await this.createChild();
      const newSubTree = await subTree.add(key, value, keyZeros);
      return this.spliceIn(newSubTree, index);
    }

    // keyZeros > layer: push rest of tree down
    const split = await this.splitAround(key);
    let left: MST | null = split[0];
    let right: MST | null = split[1];
    const extraLayersToAdd = keyZeros - layer;

    for (let i = 1; i < extraLayersToAdd; i++) {
      if (left !== null) left = await left.createParent();
      if (right !== null) right = await right.createParent();
    }

    const updated: NodeEntry[] = [];
    if (left) updated.push(left);
    updated.push(new Leaf(key, value));
    if (right) updated.push(right);

    const newRoot = await MST.create(this.storage, updated, { layer: keyZeros });
    newRoot.outdatedPointer = true;
    return newRoot;
  }

  async get(key: string): Promise<CID | null> {
    const index = await this.findGtOrEqualLeafIndex(key);
    const found = await this.atIndex(index);

    if (found && found.isLeaf() && found.key === key) {
      return found.value;
    }

    const prev = await this.atIndex(index - 1);
    if (prev && prev.isTree()) {
      return prev.get(key);
    }

    return null;
  }

  async update(key: string, value: CID): Promise<MST> {
    util.ensureValidMstKey(key);
    const index = await this.findGtOrEqualLeafIndex(key);
    const found = await this.atIndex(index);

    if (found && found.isLeaf() && found.key === key) {
      return this.updateEntry(index, new Leaf(key, value));
    }

    const prev = await this.atIndex(index - 1);
    if (prev && prev.isTree()) {
      const updatedTree = await prev.update(key, value);
      return this.updateEntry(index - 1, updatedTree);
    }

    throw new Error(`Could not find a record with key: ${key}`);
  }

  async delete(key: string): Promise<MST> {
    const altered = await this.deleteRecurse(key);
    return altered.trimTop();
  }

  async deleteRecurse(key: string): Promise<MST> {
    const index = await this.findGtOrEqualLeafIndex(key);
    const found = await this.atIndex(index);

    if (found?.isLeaf() && found.key === key) {
      const prev = await this.atIndex(index - 1);
      const next = await this.atIndex(index + 1);

      if (prev?.isTree() && next?.isTree()) {
        const merged = await prev.appendMerge(next);
        return this.newTree([
          ...(await this.slice(0, index - 1)),
          merged,
          ...(await this.slice(index + 2)),
        ]);
      }
      return this.removeEntry(index);
    }

    const prev = await this.atIndex(index - 1);
    if (prev?.isTree()) {
      const subtree = await prev.deleteRecurse(key);
      const subTreeEntries = await subtree.getEntries();
      if (subTreeEntries.length === 0) {
        return this.removeEntry(index - 1);
      }
      return this.updateEntry(index - 1, subtree);
    }

    throw new Error(`Could not find a record with key: ${key}`);
  }

  async list(count = Number.MAX_SAFE_INTEGER, after?: string, before?: string): Promise<Leaf[]> {
    const vals: Leaf[] = [];
    for await (const leaf of this.walkLeavesFrom(after || '')) {
      if (leaf.key === after) continue;
      if (vals.length >= count) break;
      if (before && leaf.key >= before) break;
      vals.push(leaf);
    }
    return vals;
  }

  async listWithPrefix(prefix: string, count = Number.MAX_SAFE_INTEGER): Promise<Leaf[]> {
    const vals: Leaf[] = [];
    for await (const leaf of this.walkLeavesFrom(prefix)) {
      if (vals.length >= count || !leaf.key.startsWith(prefix)) break;
      vals.push(leaf);
    }
    return vals;
  }

  async updateEntry(index: number, entry: NodeEntry): Promise<MST> {
    return this.newTree([
      ...(await this.slice(0, index)),
      entry,
      ...(await this.slice(index + 1)),
    ]);
  }

  async removeEntry(index: number): Promise<MST> {
    return this.newTree([
      ...(await this.slice(0, index)),
      ...(await this.slice(index + 1)),
    ]);
  }

  async atIndex(index: number): Promise<NodeEntry | null> {
    const entries = await this.getEntries();
    return entries[index] ?? null;
  }

  async slice(start?: number, end?: number): Promise<NodeEntry[]> {
    const entries = await this.getEntries();
    return entries.slice(start, end);
  }

  async spliceIn(entry: NodeEntry, index: number): Promise<MST> {
    return this.newTree([
      ...(await this.slice(0, index)),
      entry,
      ...(await this.slice(index)),
    ]);
  }

  async replaceWithSplit(
    index: number,
    left: MST | null,
    leaf: Leaf,
    right: MST | null,
  ): Promise<MST> {
    const update = await this.slice(0, index);
    if (left) update.push(left);
    update.push(leaf);
    if (right) update.push(right);
    update.push(...(await this.slice(index + 1)));
    return this.newTree(update);
  }

  async trimTop(): Promise<MST> {
    const entries = await this.getEntries();
    if (entries.length === 1 && entries[0].isTree()) {
      return entries[0].trimTop();
    }
    return this;
  }

  async splitAround(key: string): Promise<[MST | null, MST | null]> {
    const index = await this.findGtOrEqualLeafIndex(key);
    const leftData = await this.slice(0, index);
    const rightData = await this.slice(index);
    let left = await this.newTree(leftData);
    let right = await this.newTree(rightData);

    const lastInLeft = leftData[leftData.length - 1];
    if (lastInLeft?.isTree()) {
      left = await left.removeEntry(leftData.length - 1);
      const split = await lastInLeft.splitAround(key);
      if (split[0]) left = await left.append(split[0]);
      if (split[1]) right = await right.prepend(split[1]);
    }

    return [
      (await left.getEntries()).length > 0 ? left : null,
      (await right.getEntries()).length > 0 ? right : null,
    ];
  }

  async appendMerge(toMerge: MST): Promise<MST> {
    if ((await this.getLayer()) !== (await toMerge.getLayer())) {
      throw new Error('Trying to merge two nodes from different layers of the MST');
    }

    const thisEntries = await this.getEntries();
    const toMergeEntries = await toMerge.getEntries();
    const lastInLeft = thisEntries[thisEntries.length - 1];
    const firstInRight = toMergeEntries[0];

    if (lastInLeft?.isTree() && firstInRight?.isTree()) {
      const merged = await lastInLeft.appendMerge(firstInRight);
      return this.newTree([
        ...thisEntries.slice(0, thisEntries.length - 1),
        merged,
        ...toMergeEntries.slice(1),
      ]);
    }
    return this.newTree([...thisEntries, ...toMergeEntries]);
  }

  async append(entry: NodeEntry): Promise<MST> {
    const entries = await this.getEntries();
    return this.newTree([...entries, entry]);
  }

  async prepend(entry: NodeEntry): Promise<MST> {
    const entries = await this.getEntries();
    return this.newTree([entry, ...entries]);
  }

  async createChild(): Promise<MST> {
    const layer = await this.getLayer();
    return MST.create(this.storage, [], { layer: layer - 1 });
  }

  async createParent(): Promise<MST> {
    const layer = await this.getLayer();
    const parent = await MST.create(this.storage, [this], { layer: layer + 1 });
    parent.outdatedPointer = true;
    return parent;
  }

  async findGtOrEqualLeafIndex(key: string): Promise<number> {
    const entries = await this.getEntries();
    const maybeIndex = entries.findIndex((entry) => entry.isLeaf() && entry.key >= key);
    return maybeIndex >= 0 ? maybeIndex : entries.length;
  }

  async *walkFrom(key: string): AsyncIterable<NodeEntry> {
    yield this;
    const index = await this.findGtOrEqualLeafIndex(key);
    const entries = await this.getEntries();
    const found = entries[index];

    if (found && found.isLeaf() && found.key === key) {
      yield found;
    } else {
      const prev = entries[index - 1];
      if (prev) {
        if (prev.isLeaf() && prev.key === key) {
          yield prev;
        } else if (prev.isTree()) {
          yield* prev.walkFrom(key);
        }
      }
    }

    for (let i = index; i < entries.length; i++) {
      const entry = entries[i];
      if (entry.isLeaf()) {
        yield entry;
      } else {
        yield* entry.walkFrom(key);
      }
    }
  }

  async *walkLeavesFrom(key: string): AsyncIterable<Leaf> {
    for await (const node of this.walkFrom(key)) {
      if (node.isLeaf()) {
        yield node;
      }
    }
  }

  isTree(): this is MST {
    return true;
  }

  isLeaf(): this is Leaf {
    return false;
  }
}
