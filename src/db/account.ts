import { eq, or, lt } from 'drizzle-orm';
import { getDb } from './client';
import { account, refresh_token_store, secret } from './schema';
import type { Env } from '../env';
import { normalizeHandle } from '../lib/handle';

const NOW = () => Math.floor(Date.now());

export type AccountRow = typeof account.$inferSelect;
export type RefreshTokenRow = typeof refresh_token_store.$inferSelect;

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

export async function storeRefreshToken(env: Env, data: {
  id: string;
  did: string;
  expiresAt: number; // epoch seconds
  appPasswordName?: string | null;
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
    })
    .onConflictDoUpdate({
      target: refresh_token_store.id,
      set: {
        did: data.did,
        expiresAt: data.expiresAt,
        appPasswordName: data.appPasswordName ?? null,
        nextId: null,
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

export async function cleanupExpiredRefreshTokens(env: Env, now: number): Promise<number> {
  const db = getDb(env);
  const res = await db.delete(refresh_token_store).where(lt(refresh_token_store.expiresAt, now)).run();
  return res.meta.changes ?? 0;
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
