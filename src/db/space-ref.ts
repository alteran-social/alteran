import { SpaceRef as ProtocolSpaceRef } from '@atproto/syntax-spaces';
import { SpaceStorageError, type SpaceRef } from './space-types';

export function parseSpaceRef(ref: string): SpaceRef {
  try {
    const parsed = ProtocolSpaceRef.parse(ref);
    return { ref, authorityDid: parsed.spaceDid, spaceType: parsed.spaceType, skey: parsed.skey };
  } catch {
    throw new SpaceStorageError('InvalidSpaceUri', 'Invalid space URI');
  }
}
