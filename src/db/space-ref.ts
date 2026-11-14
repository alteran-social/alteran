import { SpaceRef as ProtocolSpaceRef } from '@atproto/syntax-spaces';
import type { Env } from '../env';
import { resolveSecret } from '../lib/secrets';
import { SpaceStorageError, type SpaceRef } from './space-types';

export function parseSpaceRef(ref: string): SpaceRef {
  try {
    const parsed = ProtocolSpaceRef.parse(ref);
    return { ref, authorityDid: parsed.spaceDid, spaceType: parsed.spaceType, skey: parsed.skey };
  } catch {
    throw new SpaceStorageError('InvalidSpaceUri', 'Invalid space URI');
  }
}

export async function assertLocalSpaceRepo(env: Env, repoDid: string): Promise<void> {
  const did = await resolveSecret(env.PDS_DID);
  if (!did || repoDid !== did) throw new SpaceStorageError('RepoNotFound', 'Repo is not local');
}
