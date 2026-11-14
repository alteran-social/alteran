import { LtHash } from '@atproto/space';

export const SPACE_SET_HASH_STATE_BYTES = 2048;

export type SpaceSetHashChange = {
  readonly action: 'add' | 'remove';
  readonly element: string;
};

export function spaceRecordHashElement(collection: string, rkey: string, cid: string): string {
  return `${collection}/${rkey}/${cid}`;
}

export function applySpaceSetHashChanges(
  state: Uint8Array | null,
  changes: readonly SpaceSetHashChange[],
): Uint8Array {
  if (state !== null && state.byteLength !== SPACE_SET_HASH_STATE_BYTES) {
    throw new RangeError(`Space set hash state must be ${SPACE_SET_HASH_STATE_BYTES} bytes`);
  }

  const next = new LtHash(state);
  for (const change of changes) {
    if (change.action === 'add') next.add(change.element);
    else next.remove(change.element);
  }
  return next.state();
}

export function spaceSetHashDigest(state: Uint8Array): Uint8Array {
  if (state.byteLength !== SPACE_SET_HASH_STATE_BYTES) {
    throw new RangeError(`Space set hash state must be ${SPACE_SET_HASH_STATE_BYTES} bytes`);
  }
  return new LtHash(state).digest();
}
