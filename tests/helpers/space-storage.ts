import type { Env } from '../../src/env';
import type { SpaceRef, SpaceWrite } from '../../src/db/space-types';
import { createLocalSpace as create, applySpaceWrites as write, getSpaceRecord as read } from '../../src/db/space-store';
import { createPersonalSpace as createPersonal } from '../../src/db/space-lifecycle-create';
import { beginPersonalSpaceDeletion as beginDeletion } from '../../src/db/space-lifecycle-delete';
import { loadSpaceSnapshot as snapshot } from '../../src/db/space-mutation';
import { readSpaceRepoOps as ops } from '../../src/db/space-ops';
import { spaceOwner } from './space-env';

export { commitSpaceWrites } from '../../src/db/space-mutation';

export async function createLocalSpace(env: Env, ref: string) {
  return create(env, ref, await spaceOwner(env));
}

export async function createPersonalSpace(env: Env, ref: string, policy: unknown, nonce: string) {
  return createPersonal(env, ref, policy, nonce, await spaceOwner(env));
}

export async function beginPersonalSpaceDeletion(env: Env, ref: string, nonce: string) {
  return beginDeletion(env, ref, nonce, await spaceOwner(env));
}

export async function applySpaceWrites(env: Env, ref: string, repo: string, writes: readonly SpaceWrite[]) {
  return write(env, ref, repo, writes, await spaceOwner(env));
}

export async function getSpaceRecord(env: Env, ref: string, repo: string, collection: string, rkey: string) {
  return read(env, ref, repo, collection, rkey, await spaceOwner(env));
}

export async function loadSpaceSnapshot(env: Env, ref: SpaceRef, repo: string, writes: Parameters<typeof snapshot>[3]) {
  return snapshot(env, ref, repo, writes, await spaceOwner(env));
}

export async function readSpaceRepoOps(env: Env, space: string, repo: string, input: Parameters<typeof ops>[3]) {
  return ops(env, space, repo, input, await spaceOwner(env));
}
