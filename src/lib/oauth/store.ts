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
}

export async function savePar(env: Env, id: string, rec: ParRecord): Promise<void> {
  await setSecret(env, PAR_PREFIX + id, JSON.stringify(rec));
}

export async function loadPar(env: Env, id: string): Promise<ParRecord | null> {
  const raw = await getSecret(env, PAR_PREFIX + id);
  if (!raw) return null;
  try {
    const rec = JSON.parse(raw) as ParRecord;
    if (
      typeof rec.client_id !== 'string' ||
      typeof rec.redirect_uri !== 'string' ||
      typeof rec.code_challenge !== 'string' ||
      typeof rec.scope !== 'string' ||
      typeof rec.state !== 'string' ||
      typeof rec.dpopJkt !== 'string'
    ) {
      return null;
    }
    if (rec.expiresAt && rec.expiresAt < Math.floor(Date.now() / 1000)) {
      await deletePar(env, id);
      return null;
    }
    return rec;
  } catch {
    return null;
  }
}

export async function deletePar(env: Env, id: string): Promise<void> {
  // Overwrite with expired to minimize API surface
  await setSecret(env, PAR_PREFIX + id, JSON.stringify({}));
}

export async function saveConsent(env: Env, id: string, csrf: string, expiresAt: number): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  await setSecret(env, CONSENT_PREFIX + id, JSON.stringify({ id, csrf, createdAt: now, expiresAt }));
}

export async function consumeConsent(env: Env, id: string, csrf: string): Promise<boolean> {
  const key = CONSENT_PREFIX + id;
  const raw = await getSecret(env, key);
  if (!raw) return false;
  try {
    const rec = JSON.parse(raw) as ConsentRecord;
    if (rec.expiresAt && rec.expiresAt < Math.floor(Date.now() / 1000)) return false;
    if (rec.id !== id || rec.csrf !== csrf) return false;
    const response = await env.ALTERAN_DB.prepare(
      'UPDATE secret SET value = ?, updated_at = ? WHERE key = ? AND value = ?'
    ).bind(JSON.stringify({}), Math.floor(Date.now()), key, raw).run();
    return (response.meta.changes ?? 0) === 1;
  } catch {
    return false;
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
