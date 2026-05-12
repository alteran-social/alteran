import { getDb } from '../db/client';
import { record } from '../db/schema';
import { resolveSecret } from './secrets';
import type { Env } from '../env';
import { eq } from 'drizzle-orm';

interface ProfileRecord {
  displayName?: string;
  description?: string;
  pronouns?: string;
  website?: string;
  avatar?: string;
  banner?: string;
  joinedViaStarterPack?: unknown;
  pinnedPost?: unknown;
  labels?: unknown;
  createdAt?: string;
}

export interface PrimaryActor {
  did: string;
  handle: string;
  displayName?: string;
  description?: string;
  pronouns?: string;
  website?: string;
  avatar?: string;
  banner?: string;
  labels?: unknown;
  createdAt?: string;
}

const PROFILE_COLLECTION = 'app.bsky.actor.profile';

export async function fetchProfileRecord(env: Env, did: string): Promise<ProfileRecord | null> {
  const db = getDb(env);

  const targetUri = `at://${did}/${PROFILE_COLLECTION}/self`;
  const byDid = await db.select().from(record).where(eq(record.uri, targetUri)).get();
  if (byDid?.json) {
    try {
      return JSON.parse(byDid.json) as ProfileRecord;
    } catch {
      return null;
    }
  }

  // Fallback: pick the most recent profile record regardless of DID
  // Use range scan to avoid D1 LIKE complexity limits
  // Profile URIs have format: at://<did>/app.bsky.actor.profile/self
  const prefix = `at://`;
  const suffix = `/${PROFILE_COLLECTION}/`;
  const upperBound = `at://~`; // '~' sorts after all valid DIDs

  // Find any profile record - scan from "at://" to "at://~" and filter in app
  const fallback = await env.ALTERAN_DB.prepare(
    'SELECT json FROM record WHERE uri >= ? AND uri < ? ORDER BY rowid DESC LIMIT 50'
  )
    .bind(prefix, upperBound)
    .all<{ json: string }>();

  // Filter for profile records in memory (D1 can't do complex patterns)
  if (fallback?.results) {
    for (const row of fallback.results) {
      if (row.json && typeof row.json === 'string') {
        try {
          // Check if this is a profile record by URI pattern
          const parsed = JSON.parse(row.json);
          if (parsed.$type === 'app.bsky.actor.profile') {
            return parsed as ProfileRecord;
          }
        } catch {
          continue;
        }
      }
    }
  }

  return null;
}

export async function getPrimaryActor(env: Env): Promise<PrimaryActor> {
  const did = (await resolveSecret(env.PDS_DID)) ?? 'did:example:single-user';
  const handle = (await resolveSecret(env.PDS_HANDLE)) ?? 'user.example.com';

  const profile = await fetchProfileRecord(env, did);

  return {
    did,
    handle,
    displayName: profile?.displayName ?? handle,
    description: profile?.description,
    pronouns: profile?.pronouns,
    website: profile?.website,
    avatar: profile?.avatar,
    banner: profile?.banner,
    labels: profile?.labels,
    createdAt: profile?.createdAt,
  };
}

export function matchesPrimaryActor(identifier: string | null | undefined, actor: PrimaryActor): boolean {
  if (!identifier) return false;
  const lower = identifier.toLowerCase();
  return lower === actor.did.toLowerCase() || lower === actor.handle.toLowerCase();
}

export function buildProfileViewBasic(actor: PrimaryActor) {
  const createdAt = actor.createdAt ?? new Date().toISOString();
  const labels = Array.isArray(actor.labels) ? actor.labels : [];
  return {
    $type: 'app.bsky.actor.defs#profileViewBasic',
    did: actor.did,
    handle: actor.handle,
    displayName: actor.displayName,
    pronouns: actor.pronouns,
    avatar: actor.avatar,
    createdAt,
    associated: {
      $type: 'app.bsky.actor.defs#profileAssociated',
      lists: 0,
      feedgens: 0,
      starterPacks: 0,
      labeler: false,
      chat: {
        $type: 'app.bsky.actor.defs#profileAssociatedChat',
        allowIncoming: 'all',
      },
      activitySubscription: {
        $type: 'app.bsky.actor.defs#profileAssociatedActivitySubscription',
        allowSubscriptions: 'followers',
      },
    },
    labels,
  };
}

export function buildProfileView(actor: PrimaryActor) {
  const basic = buildProfileViewBasic(actor);
  return {
    ...basic,
    $type: 'app.bsky.actor.defs#profileView',
    description: actor.description,
    indexedAt: actor.createdAt ?? new Date().toISOString(),
  };
}

export function buildProfileViewDetailed(actor: PrimaryActor, counts: {
  followers: number;
  follows: number;
  posts: number;
}) {
  const view = buildProfileView(actor);
  return {
    ...view,
    $type: 'app.bsky.actor.defs#profileViewDetailed',
    banner: actor.banner,
    website: actor.website,
    followersCount: counts.followers,
    followsCount: counts.follows,
    postsCount: counts.posts,
    viewer: {},
  };
}
