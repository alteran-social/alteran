import { and, eq, or, lt } from 'drizzle-orm';
import { getDb } from './client';
import { account, app_password, oauth_session, refresh_token_store, secret } from './schema';
import type { Env } from '../env';
import { normalizeHandle } from '../lib/handle';
import { verifyPassword } from '../lib/password';

const NOW = () => Math.floor(Date.now());

export type AccountRow = typeof account.$inferSelect;
export type AppPasswordRow = typeof app_password.$inferSelect;
export type RefreshTokenRow = typeof refresh_token_store.$inferSelect;
export type OAuthSessionRow = typeof oauth_session.$inferSelect;

function normalizeIdentifier(identifier: string): { did: string | null; handle: string | null } {
  if (!identifier) return { did: null, handle: null };
  const trimmed = identifier.trim();
  if (trimmed.startsWith('did:')) {
    return { did: trimmed, handle: null };
  }
  return { did: null, handle: normalizeHandle(trimmed) };
}

export async function getAccountByIdentifier(env: Env, identifier: string): Promise<AccountRow | null> {
  const db = getDb(env);
  const ident = normalizeIdentifier(identifier);
  const clauses = [] as any[];
  if (ident.did) clauses.push(eq(account.did, ident.did));
  if (ident.handle) clauses.push(eq(account.handle, ident.handle));
  if (clauses.length === 0) return null;
  const where = clauses.length === 1 ? clauses[0] : or(...clauses);
  const row = await db.select().from(account).where(where).get();
  return row ?? null;
}

export async function createAccount(env: Env, data: {
  did: string;
  handle: string;
  passwordScrypt: string | null;
  email?: string | null;
}): Promise<void> {
  const db = getDb(env);
  const now = NOW();
  await db
    .insert(account)
    .values({
      did: data.did,
      handle: normalizeHandle(data.handle),
      passwordScrypt: data.passwordScrypt ?? null,
      email: data.email ?? null,
      createdAt: now,
      updatedAt: now,
    })
    .onConflictDoUpdate({
      target: account.did,
      set: {
        handle: normalizeHandle(data.handle),
        passwordScrypt: data.passwordScrypt ?? null,
        email: data.email ?? null,
        updatedAt: now,
      },
    });
}

export async function updateAccountPassword(env: Env, did: string, passwordScrypt: string): Promise<void> {
  const db = getDb(env);
  await db
    .update(account)
    .set({ passwordScrypt, updatedAt: NOW() })
    .where(eq(account.did, did))
    .run();
}

export async function createAppPasswordRecord(env: Env, data: {
  did: string;
  name: string;
  passwordScrypt: string;
  privileged: boolean;
  createdAt?: number;
}): Promise<boolean> {
  const response = await env.ALTERAN_DB.prepare(
    `INSERT INTO app_password (did, name, password_scrypt, created_at, privileged)
     SELECT ?, ?, ?, ?, ?
     WHERE NOT EXISTS (
       SELECT 1 FROM app_password WHERE did = ? AND name = ?
     )`,
  ).bind(
    data.did,
    data.name,
    data.passwordScrypt,
    data.createdAt ?? NOW(),
    data.privileged ? 1 : 0,
    data.did,
    data.name,
  ).run();
  return (response.meta.changes ?? 0) === 1;
}

export async function listAppPasswords(env: Env, did: string): Promise<AppPasswordRow[]> {
  const db = getDb(env);
  return db
    .select()
    .from(app_password)
    .where(eq(app_password.did, did))
    .orderBy(app_password.createdAt, app_password.name)
    .all();
}

export async function getAppPassword(
  env: Env,
  did: string,
  name: string,
): Promise<AppPasswordRow | null> {
  const db = getDb(env);
  const row = await db
    .select()
    .from(app_password)
    .where(and(eq(app_password.did, did), eq(app_password.name, name)))
    .get();
  return row ?? null;
}

export async function verifyAppPasswordForLogin(
  env: Env,
  did: string,
  password: string,
): Promise<{ name: string; privileged: boolean } | null> {
  for (const candidate of await listAppPasswords(env, did)) {
    if (await verifyPassword(password, candidate.passwordScrypt)) {
      return {
        name: candidate.name,
        privileged: !!candidate.privileged,
      };
    }
  }
  return null;
}

export async function revokeAppPasswordRecord(
  env: Env,
  did: string,
  name: string,
): Promise<boolean> {
  const response = await env.ALTERAN_DB.prepare(
    'DELETE FROM app_password WHERE did = ? AND name = ?',
  ).bind(did, name).run();
  return (response.meta.changes ?? 0) > 0;
}

export async function revokeRefreshTokensForAppPassword(
  env: Env,
  did: string,
  name: string,
  now: number = Math.floor(Date.now() / 1000),
): Promise<void> {
  await env.ALTERAN_DB.prepare(
    `UPDATE refresh_token
     SET revoked_at = ?
     WHERE did = ?
       AND app_password_name = ?
       AND token_kind = 'legacy'
       AND revoked_at IS NULL`,
  ).bind(now, did, name).run();
}

export async function storeRefreshToken(env: Env, data: {
  id: string;
  did: string;
  expiresAt: number; // epoch seconds
  appPasswordName?: string | null;
  tokenKind?: 'legacy' | 'oauth';
  oauthSessionId?: string | null;
  clientId?: string | null;
  clientAuthMethod?: string | null;
  clientAuthKeyId?: string | null;
  dpopJkt?: string | null;
  oauthScope?: string | null;
  accessJti?: string | null;
}): Promise<void> {
  const db = getDb(env);
  await db
    .insert(refresh_token_store)
    .values({
      id: data.id,
      did: data.did,
      expiresAt: data.expiresAt,
      appPasswordName: data.appPasswordName ?? null,
      nextId: null,
      tokenKind: data.tokenKind ?? 'legacy',
      oauthSessionId: data.oauthSessionId ?? null,
      clientId: data.clientId ?? null,
      clientAuthMethod: data.clientAuthMethod ?? null,
      clientAuthKeyId: data.clientAuthKeyId ?? null,
      dpopJkt: data.dpopJkt ?? null,
      oauthScope: data.oauthScope ?? null,
      accessJti: data.accessJti ?? null,
      revokedAt: null,
    })
    .onConflictDoUpdate({
      target: refresh_token_store.id,
      set: {
        did: data.did,
        expiresAt: data.expiresAt,
        appPasswordName: data.appPasswordName ?? null,
        nextId: null,
        tokenKind: data.tokenKind ?? 'legacy',
        oauthSessionId: data.oauthSessionId ?? null,
        clientId: data.clientId ?? null,
        clientAuthMethod: data.clientAuthMethod ?? null,
        clientAuthKeyId: data.clientAuthKeyId ?? null,
        dpopJkt: data.dpopJkt ?? null,
        oauthScope: data.oauthScope ?? null,
        accessJti: data.accessJti ?? null,
        revokedAt: null,
      },
    });
}

export async function markRefreshTokenRotated(env: Env, id: string, nextId: string, graceExpiresAt: number): Promise<void> {
  const db = getDb(env);
  await db
    .update(refresh_token_store)
    .set({ nextId, expiresAt: graceExpiresAt })
    .where(eq(refresh_token_store.id, id))
    .run();
}

export async function getRefreshToken(env: Env, id: string): Promise<RefreshTokenRow | null> {
  const db = getDb(env);
  const row = await db
    .select()
    .from(refresh_token_store)
    .where(eq(refresh_token_store.id, id))
    .get();
  return row ?? null;
}

export async function deleteRefreshToken(env: Env, id: string): Promise<void> {
  const db = getDb(env);
  await db.delete(refresh_token_store).where(eq(refresh_token_store.id, id)).run();
}

export async function revokeRefreshToken(env: Env, id: string, now: number = Math.floor(Date.now() / 1000)): Promise<void> {
  const db = getDb(env);
  await db
    .update(refresh_token_store)
    .set({ revokedAt: now })
    .where(eq(refresh_token_store.id, id))
    .run();
}

export async function markOAuthRefreshUsed(env: Env, id: string, nextId: string, now: number): Promise<void> {
  const response = await env.ALTERAN_DB.prepare(
    'UPDATE refresh_token SET next_id = ?, revoked_at = ? WHERE id = ? AND token_kind = ? AND next_id IS NULL AND revoked_at IS NULL'
  ).bind(nextId, now, id, 'oauth').run();
  if ((response.meta.changes ?? 0) !== 1) {
    throw new Error('oauth refresh token was already used');
  }
}

export async function createOAuthSession(env: Env, data: {
  id: string;
  did: string;
  clientId: string;
  clientAuthMethod: string;
  clientAuthKeyId?: string | null;
  dpopJkt: string;
  scope: string;
  currentRefreshTokenId: string;
  accessJti: string;
  expiresAt: number;
}): Promise<void> {
  const db = getDb(env);
  const now = Math.floor(Date.now() / 1000);
  await db
    .insert(oauth_session)
    .values({
      id: data.id,
      did: data.did,
      clientId: data.clientId,
      clientAuthMethod: data.clientAuthMethod,
      clientAuthKeyId: data.clientAuthKeyId ?? null,
      dpopJkt: data.dpopJkt,
      scope: data.scope,
      currentRefreshTokenId: data.currentRefreshTokenId,
      accessJti: data.accessJti,
      createdAt: now,
      updatedAt: now,
      expiresAt: data.expiresAt,
      revokedAt: null,
    });
}

export async function getOAuthSession(env: Env, id: string): Promise<OAuthSessionRow | null> {
  const db = getDb(env);
  const row = await db
    .select()
    .from(oauth_session)
    .where(eq(oauth_session.id, id))
    .get();
  return row ?? null;
}

export async function updateOAuthSessionCurrent(env: Env, id: string, data: {
  currentRefreshTokenId: string;
  previousRefreshTokenId?: string;
  accessJti: string;
  expiresAt: number;
  now?: number;
}): Promise<void> {
  const now = data.now ?? Math.floor(Date.now() / 1000);
  const response = data.previousRefreshTokenId
    ? await env.ALTERAN_DB.prepare(
        'UPDATE oauth_session SET current_refresh_token_id = ?, access_jti = ?, expires_at = ?, updated_at = ? WHERE id = ? AND current_refresh_token_id = ? AND revoked_at IS NULL'
      ).bind(data.currentRefreshTokenId, data.accessJti, data.expiresAt, now, id, data.previousRefreshTokenId).run()
    : await env.ALTERAN_DB.prepare(
        'UPDATE oauth_session SET current_refresh_token_id = ?, access_jti = ?, expires_at = ?, updated_at = ? WHERE id = ? AND revoked_at IS NULL'
      ).bind(data.currentRefreshTokenId, data.accessJti, data.expiresAt, now, id).run();
  if ((response.meta.changes ?? 0) !== 1) {
    throw new Error('oauth session changed during refresh');
  }
}

export async function revokeOAuthSession(env: Env, id: string, now: number = Math.floor(Date.now() / 1000)): Promise<void> {
  const db = getDb(env);
  await db
    .update(oauth_session)
    .set({ revokedAt: now, updatedAt: now })
    .where(eq(oauth_session.id, id))
    .run();
}

export async function cleanupExpiredRefreshTokens(env: Env, now: number): Promise<number> {
  const db = getDb(env);
  const response = await db.delete(refresh_token_store).where(lt(refresh_token_store.expiresAt, now)).run();
  return response.meta.changes ?? 0;
}

export async function cleanupExpiredOAuthReplaySecrets(env: Env, now: number): Promise<number> {
  const response = await env.ALTERAN_DB.prepare(`
    DELETE FROM secret
    WHERE (key LIKE 'oauth:dpop:jti:%' OR key LIKE 'oauth:client-assertion:jti:%')
      AND CAST(json_extract(value, '$.exp') AS INTEGER) <= ?
  `).bind(now).run();
  return response.meta.changes ?? 0;
}

export async function getSecret(env: Env, key: string): Promise<string | null> {
  const db = getDb(env);
  const row = await db.select().from(secret).where(eq(secret.key, key)).get();
  return row?.value ?? null;
}

export async function setSecret(env: Env, key: string, value: string): Promise<void> {
  const db = getDb(env);
  await db
    .insert(secret)
    .values({ key, value, updatedAt: NOW() })
    .onConflictDoUpdate({
      target: secret.key,
      set: { value, updatedAt: NOW() },
    });
}

export async function createSecretOnce(env: Env, key: string, value: string): Promise<boolean> {
  const response = await env.ALTERAN_DB.prepare(
    'INSERT OR IGNORE INTO secret (key, value, updated_at) VALUES (?, ?, ?)'
  ).bind(key, value, NOW()).run();
  return (response.meta.changes ?? 0) === 1;
}

export async function getOrCreateSecret(env: Env, key: string, factory: () => Promise<string>): Promise<string> {
  // Check if secret already exists
  const existing = await getSecret(env, key);
  if (existing) return existing;

  // Generate a new value
  const value = await factory();

  // Use onConflictDoNothing to avoid race conditions where multiple Workers
  // might try to create the secret simultaneously. The first one wins.
  const db = getDb(env);
  await db
    .insert(secret)
    .values({ key, value, updatedAt: NOW() })
    .onConflictDoNothing();

  // Re-read to get the actual stored value (might be from another Worker)
  const stored = await getSecret(env, key);
  return stored ?? value;
}
