import type { Env } from '../../env';
import { getSecret, setSecret } from '../../db/account';

const PAR_PREFIX = 'oauth:par:';
const CODE_PREFIX = 'oauth:code:';
const CONSENT_PREFIX = 'oauth:consent:';

export interface ParRecord {
  client_id: string;
  redirect_uri: string;
  code_challenge: string;
  code_challenge_method: 'S256';
  scope: string;
  state: string;
  login_hint?: string;
  prompt?: string;
  dpopJkt: string;
  clientAuthMethod: 'none' | 'private_key_jwt';
  clientAuthKeyId?: string | null;
  createdAt: number;
  expiresAt: number;
}

export interface CodeRecord {
  code: string;
  client_id: string;
  redirect_uri: string;
  code_challenge: string;
  scope: string;
  dpopJkt: string;
  clientAuthMethod: 'none' | 'private_key_jwt';
  clientAuthKeyId?: string | null;
  did: string;
  createdAt: number;
  expiresAt: number;
  used?: boolean;
}

export interface ConsentRecord {
  id: string;
  csrf: string;
  createdAt: number;
  expiresAt: number;
  parValue: string;
}

export type ParSnapshot = { readonly record: ParRecord; readonly value: string };

export async function savePar(env: Env, id: string, rec: ParRecord): Promise<void> {
  await setSecret(env, PAR_PREFIX + id, JSON.stringify(rec));
}

export async function loadPar(env: Env, id: string): Promise<ParRecord | null> {
  return (await loadParSnapshot(env, id))?.record ?? null;
}

export async function loadParSnapshot(env: Env, id: string): Promise<ParSnapshot | null> {
  const raw = await getSecret(env, PAR_PREFIX + id);
  if (!raw) return null;
  try {
    const rec = JSON.parse(raw) as ParRecord;
    if (
      !rec || typeof rec !== 'object' ||
      typeof rec.client_id !== 'string' || !rec.client_id ||
      typeof rec.redirect_uri !== 'string' || !rec.redirect_uri ||
      typeof rec.code_challenge !== 'string' || !rec.code_challenge ||
      rec.code_challenge_method !== 'S256' ||
      typeof rec.scope !== 'string' || !rec.scope ||
      typeof rec.state !== 'string' ||
      typeof rec.dpopJkt !== 'string' || !rec.dpopJkt ||
      (rec.clientAuthMethod !== 'none' && rec.clientAuthMethod !== 'private_key_jwt') ||
      (rec.clientAuthKeyId !== undefined && rec.clientAuthKeyId !== null && typeof rec.clientAuthKeyId !== 'string') ||
      (rec.login_hint !== undefined && typeof rec.login_hint !== 'string') ||
      (rec.prompt !== undefined && typeof rec.prompt !== 'string') ||
      !Number.isSafeInteger(rec.createdAt) || !Number.isSafeInteger(rec.expiresAt) ||
      rec.createdAt < 0 || rec.expiresAt <= rec.createdAt
    ) {
      return null;
    }
    if (rec.expiresAt < Math.floor(Date.now() / 1000)) {
      await deleteParSnapshot(env, id, raw);
      return null;
    }
    return { record: rec, value: raw };
  } catch {
    return null;
  }
}

export async function deleteParSnapshot(env: Env, id: string, value: string): Promise<void> {
  await env.ALTERAN_DB.prepare(
    'UPDATE secret SET value = ?, updated_at = ? WHERE key = ? AND value = ?',
  ).bind(JSON.stringify({}), Date.now(), PAR_PREFIX + id, value).run();
}

export async function saveConsent(env: Env, id: string, csrf: string, expiresAt: number, parValue: string): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  await setSecret(env, CONSENT_PREFIX + id, JSON.stringify({ id, csrf, createdAt: now, expiresAt, parValue }));
}

export async function consumeConsent(env: Env, id: string, csrf: string): Promise<ConsentRecord | null> {
  const key = CONSENT_PREFIX + id;
  const raw = await getSecret(env, key);
  if (!raw) return null;
  try {
    const rec = JSON.parse(raw) as ConsentRecord;
    if (!rec || typeof rec !== 'object' || rec.id !== id || rec.csrf !== csrf ||
      typeof rec.parValue !== 'string' || !rec.parValue ||
      !Number.isSafeInteger(rec.createdAt) || !Number.isSafeInteger(rec.expiresAt) ||
      rec.createdAt < 0 || rec.expiresAt <= rec.createdAt ||
      rec.expiresAt < Math.floor(Date.now() / 1000)) return null;
    const response = await env.ALTERAN_DB.prepare(
      'UPDATE secret SET value = ?, updated_at = ? WHERE key = ? AND value = ?'
    ).bind(JSON.stringify({}), Math.floor(Date.now()), key, raw).run();
    return (response.meta.changes ?? 0) === 1 ? rec : null;
  } catch {
    return null;
  }
}

export async function saveCode(env: Env, code: string, rec: CodeRecord): Promise<void> {
  await setSecret(env, CODE_PREFIX + code, JSON.stringify(rec));
}

export async function loadCode(env: Env, code: string): Promise<CodeRecord | null> {
  const raw = await getSecret(env, CODE_PREFIX + code);
  if (!raw) return null;
  try {
    const rec = JSON.parse(raw) as CodeRecord;
    if (rec.expiresAt && rec.expiresAt < Math.floor(Date.now() / 1000)) return null;
    return rec;
  } catch {
    return null;
  }
}

export async function consumeCode(env: Env, code: string): Promise<CodeRecord | null> {
  const key = CODE_PREFIX + code;
  const raw = await getSecret(env, key);
  if (!raw) return null;
  try {
    const rec = JSON.parse(raw) as CodeRecord;
    if (rec.expiresAt && rec.expiresAt < Math.floor(Date.now() / 1000)) return null;
    if (rec.used) return null;
    const used = JSON.stringify({ ...rec, used: true });
    const response = await env.ALTERAN_DB.prepare(
      'UPDATE secret SET value = ?, updated_at = ? WHERE key = ? AND value = ?'
    ).bind(used, Math.floor(Date.now()), key, raw).run();
    return (response.meta.changes ?? 0) === 1 ? rec : null;
  } catch {
    return null;
  }
}
