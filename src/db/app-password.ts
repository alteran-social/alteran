import { and, eq, isNull } from 'drizzle-orm';
import { getDb } from './client';
import { app_password, refresh_token_store, type AppPasswordRow } from './schema';
import { verifyPassword } from '../lib/password';
import { isAppPasswordFormat } from '../lib/app-password';
import type { Env } from '../env';

export type { AppPasswordRow };

export type CreateAppPasswordInput = {
  did: string;
  name: string;
  passwordScrypt: string;
  privileged: boolean;
};

export async function createAppPasswordRow(env: Env, data: CreateAppPasswordInput): Promise<AppPasswordRow> {
  const createdAt = Math.floor(Date.now() / 1000);
  const db = getDb(env);
  await db.insert(app_password).values({ ...data, createdAt });
  return { ...data, createdAt };
}

export async function listAppPasswordRows(env: Env, did: string): Promise<AppPasswordRow[]> {
  const db = getDb(env);
  return await db.select().from(app_password).where(eq(app_password.did, did)).all();
}

export async function findAppPasswordByName(env: Env, did: string, name: string): Promise<AppPasswordRow | null> {
  const db = getDb(env);
  const row = await db
    .select()
    .from(app_password)
    .where(and(eq(app_password.did, did), eq(app_password.name, name)))
    .get();
  return row ?? null;
}

export async function findMatchingAppPassword(
  env: Env,
  did: string,
  candidatePassword: string,
): Promise<AppPasswordRow | null> {
  // Format gate bounds the scrypt amplification surface for arbitrary login
  // bodies and matches the reference PDS. The trade-off — revealing whether
  // an input "looks like" an app password — is acceptable for the
  // single-user target.
  if (!isAppPasswordFormat(candidatePassword)) return null;
  const rows = await listAppPasswordRows(env, did);
  for (const row of rows) {
    if (await verifyPassword(candidatePassword, row.passwordScrypt)) {
      return row;
    }
  }
  return null;
}

export async function deleteAppPasswordRow(env: Env, did: string, name: string): Promise<boolean> {
  const db = getDb(env);
  const response = await db
    .delete(app_password)
    .where(and(eq(app_password.did, did), eq(app_password.name, name)))
    .run();
  return (response.meta.changes ?? 0) > 0;
}

export async function revokeRefreshTokensByAppPasswordName(
  env: Env,
  did: string,
  name: string,
  nowSec: number = Math.floor(Date.now() / 1000),
): Promise<number> {
  const db = getDb(env);
  const response = await db
    .update(refresh_token_store)
    .set({ revokedAt: nowSec })
    .where(
      and(
        eq(refresh_token_store.did, did),
        eq(refresh_token_store.appPasswordName, name),
        isNull(refresh_token_store.revokedAt),
      ),
    )
    .run();
  return response.meta.changes ?? 0;
}
