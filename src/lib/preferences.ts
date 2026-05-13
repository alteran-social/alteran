import type { Env } from '../env';
import { resolveSecret } from './secrets';
import { ServerMisconfigured } from './errors';

// No defaults — return empty when nothing stored to avoid local fallbacks

export async function getActorPreferences(env: Env): Promise<{ did: string; preferences: any[] }> {
  const did = await resolveSecret(env.PDS_DID);
  if (!did) throw new ServerMisconfigured('PDS_DID is not configured');
  const row = await env.ALTERAN_DB.prepare('SELECT json FROM actor_preferences WHERE did = ?')
    .bind(did)
    .first<{ json: string }>();

  if (!row?.json) {
    return { did, preferences: [] };
  }

  try {
    const parsed = JSON.parse(row.json);
    const preferences = Array.isArray(parsed) ? parsed : [];
    return { did, preferences };
  } catch {
    return { did, preferences: [] };
  }
}

export async function setActorPreferences(env: Env, preferences: any[]): Promise<void> {
  const did = await resolveSecret(env.PDS_DID);
  if (!did) throw new ServerMisconfigured('PDS_DID is not configured');
  const now = Date.now();
  await env.ALTERAN_DB.prepare(
    'INSERT INTO actor_preferences (did, json, updated_at) VALUES (?, ?, ?) ON CONFLICT(did) DO UPDATE SET json = excluded.json, updated_at = excluded.updated_at'
  )
    .bind(did, JSON.stringify(preferences ?? []), now)
    .run();
}
