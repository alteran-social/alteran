import type { BlobReference } from '../lib/repo-write-data';

export const MAX_SPACE_WRITE_BYTES = 1_000_000;
export const MAX_SPACE_WRITES = 200;

export type SpaceRef = {
  readonly ref: string;
  readonly authorityDid: string;
  readonly spaceType: string;
  readonly skey: string;
};

export type SpaceWrite =
  | { readonly action: 'create' | 'update'; readonly collection: string; readonly rkey: string; readonly record: unknown }
  | { readonly action: 'delete'; readonly collection: string; readonly rkey: string };

export type PreparedSpaceWrite =
  | {
    readonly action: 'create' | 'update';
    readonly collection: string;
    readonly rkey: string;
    readonly cid: string;
    readonly value: Uint8Array;
    readonly blobs: readonly BlobReference[];
  }
  | { readonly action: 'delete'; readonly collection: string; readonly rkey: string };

export type SpaceOperation = {
  readonly collection: string;
  readonly rkey: string;
  readonly cid: string | null;
  readonly prev: string | null;
};

export type SpaceRepoState = {
  readonly rev: string | null;
  readonly setHash: Uint8Array;
  readonly generation: number;
};

export type SpaceCommit = SpaceRepoState & {
  readonly rev: string;
  readonly data: Uint8Array;
  readonly operations: readonly SpaceOperation[];
};

export class SpaceStorageError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = 'SpaceStorageError';
  }
}
