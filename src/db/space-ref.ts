import { SpaceRef as ProtocolSpaceRef } from '@atproto/syntax-spaces';
import type { Env } from '../env';
import { resolveSecret } from '../lib/secrets';
import { SpaceStorageError, type SpaceRef } from './space-types';
import { isSpaceDid } from '../lib/spaces/space-did';

export function parseSpaceRef(ref: string): SpaceRef {
  try {
    if (typeof ref !== 'string' || ref.length > 8192) throw new Error('Invalid space URI');
    const parsed = ProtocolSpaceRef.parse(ref);
    if (parsed.toString() !== ref || !isSpaceDid(parsed.spaceDid)) throw new Error('Invalid space URI');
    return { ref, authorityDid: parsed.spaceDid, spaceType: parsed.spaceType, skey: parsed.skey };
  } catch {
    throw new SpaceStorageError('InvalidSpaceUri', 'Invalid space URI');
  }
}

export async function assertLocalSpaceRepo(env: Env, repoDid: string): Promise<void> {
  const did = await resolveSecret(env.PDS_DID);
  if (!isSpaceDid(did) || repoDid !== did) throw new SpaceStorageError('RepoNotFound', 'Repo is not local');
}
