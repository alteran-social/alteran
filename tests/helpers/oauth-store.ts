import type { Env } from '../../src/env';
import { setSecret } from '../../src/db/account';
import { getDb } from '../../src/db/client';
import { oauth_session } from '../../src/db/schema';
import type { CodeRecord } from '../../src/lib/oauth/store';
import { eq } from 'drizzle-orm';

export async function saveCode(env: Env, code: string, record: CodeRecord): Promise<void> {
  await setSecret(env, `oauth:code:${code}`, JSON.stringify(record));
}

export async function createOAuthSession(env: Env, data: {
  id: string;
  did: string;
  clientId: string;
  clientAuthMethod: string;
  clientAuthKeyId?: string | null;
  clientAuthKeyBinding?: string | null;
  dpopJkt: string;
  scope: string;
  currentRefreshTokenId: string;
  accessJti: string;
  expiresAt: number;
}): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  await getDb(env).insert(oauth_session).values({ ...data, clientAuthKeyId: data.clientAuthKeyId ?? null,
    clientAuthKeyBinding: data.clientAuthKeyBinding ?? null, createdAt: now, updatedAt: now, revokedAt: null });
}

export async function getOAuthSession(env: Env, id: string) {
  return await getDb(env).select().from(oauth_session).where(eq(oauth_session.id, id)).get() ?? null;
}
