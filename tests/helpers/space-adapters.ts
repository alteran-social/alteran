import type { Env } from '../../src/env';
import type { SpaceRef, SpaceWrite, PreparedSpaceWrite } from '../../src/db/space-types';
import { createLocalSpace as create, applySpaceWrites as write, getSpaceRecord as read } from '../../src/db/space-store';
import { loadSpaceSnapshot as load } from '../../src/db/space-mutation';
import { acquireSpaceSnapshot as acquire } from '../../src/db/space-snapshot';
import { pruneSpaceRecordVersionsPage as prune, type SpaceVersionGcCursor } from '../../src/db/space-version-gc';
import { streamSpaceRepoArchive as stream } from '../../src/services/space-repo-export';
import { claimSpaceQuarantine as claim } from '../../src/db/space-quarantine';
import { spaceOwner } from './space-env';

export { commitSpaceWrites } from '../../src/db/space-mutation';
export { readSpaceSnapshotPage, releaseSpaceSnapshot } from '../../src/db/space-snapshot';
export { stepSpaceQuarantine } from '../../src/db/space-quarantine';
export { SPACE_VERSION_GC_DELETE_SQL, SPACE_VERSION_GC_FIRST_SQL, SPACE_VERSION_GC_NEXT_SQL,
  type SpaceVersionGcCursor } from '../../src/db/space-version-gc';

// General storage fixtures use the active test account. Ownership races use
// the underlying APIs directly with an explicitly captured incarnation.
export async function createLocalSpace(env: Env, space: string) {
  return await create(env, space, await spaceOwner(env));
}

export async function applySpaceWrites(env: Env, space: string, repo: string, writes: readonly SpaceWrite[]) {
  return await write(env, space, repo, writes, await spaceOwner(env));
}

export async function getSpaceRecord(env: Env, space: string, repo: string, collection: string, rkey: string) {
  return await read(env, space, repo, collection, rkey, await spaceOwner(env));
}

export async function loadSpaceSnapshot(env: Env, ref: SpaceRef, repo: string, writes: readonly PreparedSpaceWrite[]) {
  return await load(env, ref, repo, writes, await spaceOwner(env));
}

export async function acquireSpaceSnapshot(env: Env, space: string, repo: string) {
  return await acquire(env, space, repo, await spaceOwner(env));
}

export async function pruneSpaceRecordVersionsPage(
  env: Env, space: string, repo: string, cursor: SpaceVersionGcCursor | null = null, limit?: number,
) {
  return await prune(env, space, repo, await spaceOwner(env), cursor, limit);
}

export async function streamSpaceRepoArchive(env: Env, space: string, repo: string, signal?: AbortSignal) {
  return await stream(env, space, repo, await spaceOwner(env), signal);
}

export async function claimSpaceQuarantine(env: Env, space: string, repo: string) {
  return await claim(env, space, repo, await spaceOwner(env, repo));
}
