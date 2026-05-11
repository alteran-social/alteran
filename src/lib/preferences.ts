import type { Env } from '../env';
import { resolveSecret } from './secrets';
import { ServerMisconfigured } from './errors';

let tableEnsured = false;

async function ensureTable(env: Env) {
  if (tableEnsured) return;
  await env.DB.exec(
    'CREATE TABLE IF NOT EXISTS actor_preferences (did TEXT PRIMARY KEY, json TEXT NOT NULL, updated_at INTEGER NOT NULL)'
  );
  tableEnsured = true;
}

// No defaults — return empty when nothing stored to avoid local fallbacks

export async function getActorPreferences(env: Env): Promise<{ did: string; preferences: any[] }> {
  await ensureTable(env);
  const did = await resolveSecret(env.PDS_DID);
  if (!did) throw new ServerMisconfigured('PDS_DID is not configured');
  const row = await env.DB.prepare('SELECT json FROM actor_preferences WHERE did = ?')
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
  await ensureTable(env);
  const did = await resolveSecret(env.PDS_DID);
  if (!did) throw new ServerMisconfigured('PDS_DID is not configured');
  const now = Date.now();
  await env.DB.prepare(
    'INSERT INTO actor_preferences (did, json, updated_at) VALUES (?, ?, ?) ON CONFLICT(did) DO UPDATE SET json = excluded.json, updated_at = excluded.updated_at'
  )
    .bind(did, JSON.stringify(preferences ?? []), now)
    .run();
}
