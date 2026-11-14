import type { Env } from '../../src/env';
import { createAccount } from '../../src/db/account';
import { setAccountState } from '../../src/db/dal';
import { loadActiveSpaceOwner } from '../../src/db/space-owner';
import { resolveSecret } from '../../src/lib/secrets';
import { makeEnv } from './env';

export async function makeSpaceEnv(overrides: Partial<Env> = {}): Promise<Env> {
  const env = await makeEnv(overrides);
  const did = await resolveSecret(env.PDS_DID);
  const handle = await resolveSecret(env.PDS_HANDLE);
  if (!did || !handle) throw new Error('Missing Space test identity');
  await createAccount(env, { did, handle, passwordScrypt: null });
  await setAccountState(env, did, { tag: 'active' });
  return env;
}

export async function spaceOwner(env: Env, did?: string): Promise<string> {
  const identity = did ?? await resolveSecret(env.PDS_DID);
  if (!identity) throw new Error('Missing Space test identity');
  const owner = await loadActiveSpaceOwner(env, identity);
  if (!owner) throw new Error('Missing active Space test owner');
  return owner.incarnation;
}
