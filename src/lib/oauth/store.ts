import type { Env } from '../../env';
import { setSecret } from '../../db/account';

const PAR_PREFIX = 'oauth:par:';
const CODE_PREFIX = 'oauth:code:';
const CONSENT_PREFIX = 'oauth:consent:';
export const MAX_PAR_BYTES = 64 * 1024;
export const MAX_CODE_BYTES = 128 * 1024;
const MAX_CONSENT_BYTES = 512 * 1024;

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
  clientAuthKeyBinding?: 'jwk-thumbprint-v1' | null;
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
  clientAuthKeyBinding?: 'jwk-thumbprint-v1' | null;
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
export type CodeSnapshot = { readonly record: CodeRecord; readonly value: string };

function boundedText(value: string, maximum: number): boolean {
  return value.length <= maximum && new TextEncoder().encode(value).byteLength <= maximum;
}

async function getBoundedSecret(env: Env, key: string, maximum: number): Promise<string | null> {
  const row = await env.ALTERAN_DB.prepare(`SELECT CASE WHEN typeof(value) = 'text'
    AND length(CAST(value AS BLOB)) <= ? THEN value ELSE NULL END AS value FROM secret WHERE key = ?`)
    .bind(maximum, key).first<{ value: string | null }>();
  return typeof row?.value === 'string' ? row.value : null;
}

export function parRecordFits(record: ParRecord): boolean {
  return boundedText(JSON.stringify(record), MAX_PAR_BYTES);
}

export async function savePar(env: Env, id: string, rec: ParRecord): Promise<void> {
  if (!boundedText(id, 8192) || !parRecordFits(rec)) throw new Error('PAR record exceeds storage limit');
  await setSecret(env, PAR_PREFIX + id, JSON.stringify(rec));
}

export async function loadPar(env: Env, id: string): Promise<ParRecord | null> {
  return (await loadParSnapshot(env, id))?.record ?? null;
}

export async function loadParSnapshot(env: Env, id: string): Promise<ParSnapshot | null> {
  if (!id || !boundedText(id, 8192)) return null;
  const raw = await getBoundedSecret(env, PAR_PREFIX + id, MAX_PAR_BYTES);
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
      (rec.clientAuthKeyBinding !== undefined && rec.clientAuthKeyBinding !== null && rec.clientAuthKeyBinding !== 'jwk-thumbprint-v1') ||
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
  if (!boundedText(id, 8192) || !boundedText(csrf, 8192) || !boundedText(parValue, MAX_PAR_BYTES)) {
    throw new Error('Consent record exceeds storage limit');
  }
  const value = JSON.stringify({ id, csrf, createdAt: now, expiresAt, parValue });
  if (!boundedText(value, MAX_CONSENT_BYTES)) throw new Error('Consent record exceeds storage limit');
  await setSecret(env, CONSENT_PREFIX + id, value);
}

export async function consumeConsent(env: Env, id: string, csrf: string): Promise<ConsentRecord | null> {
  const key = CONSENT_PREFIX + id;
  if (!id || !boundedText(id, 8192) || !boundedText(csrf, 8192)) return null;
  const raw = await getBoundedSecret(env, key, MAX_CONSENT_BYTES);
  if (!raw) return null;
  try {
    const rec = JSON.parse(raw) as ConsentRecord;
    if (!rec || typeof rec !== 'object' || rec.id !== id || rec.csrf !== csrf ||
      typeof rec.parValue !== 'string' || !rec.parValue || !boundedText(rec.parValue, MAX_PAR_BYTES) ||
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

/** Read a validated immutable code without consuming it. */
export async function loadCodeSnapshot(env: Env, code: string): Promise<CodeSnapshot | null> {
  if (!code || !boundedText(code, 8192)) return null;
  const raw = await getBoundedSecret(env, CODE_PREFIX + code, MAX_CODE_BYTES);
  if (!raw) return null;
  try {
    const rec = JSON.parse(raw) as CodeRecord;
    if (!rec || typeof rec !== 'object' || Array.isArray(rec) || rec.code !== code ||
      typeof rec.client_id !== 'string' || !rec.client_id ||
      typeof rec.redirect_uri !== 'string' || !rec.redirect_uri ||
      typeof rec.code_challenge !== 'string' || !rec.code_challenge ||
      typeof rec.scope !== 'string' || !rec.scope ||
      typeof rec.dpopJkt !== 'string' || !rec.dpopJkt ||
      typeof rec.did !== 'string' || !rec.did ||
      (rec.clientAuthMethod !== 'none' && rec.clientAuthMethod !== 'private_key_jwt') ||
      (rec.clientAuthKeyId !== undefined && rec.clientAuthKeyId !== null && typeof rec.clientAuthKeyId !== 'string') ||
      (rec.clientAuthKeyBinding !== undefined && rec.clientAuthKeyBinding !== null && rec.clientAuthKeyBinding !== 'jwk-thumbprint-v1') ||
      (rec.used !== undefined && rec.used !== false) ||
      !Number.isSafeInteger(rec.createdAt) || !Number.isSafeInteger(rec.expiresAt) ||
      rec.createdAt < 0 || rec.expiresAt <= rec.createdAt) return null;
    return { record: rec, value: raw };
  } catch {
    return null;
  }
}
