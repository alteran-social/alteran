import type { Env } from '../env';
import type { OAuthSessionRow, RefreshTokenRow } from './account';

const TEXT_LIMIT = 131_072;
const MAX_INTEGER = 9_007_199_254_740_991;
const REFRESH_COLUMNS = [
  ['id', 'id'], ['did', 'did'], ['expires_at', 'expiresAt'], ['app_password_name', 'appPasswordName'],
  ['next_id', 'nextId'], ['token_kind', 'tokenKind'], ['oauth_session_id', 'oauthSessionId'],
  ['client_id', 'clientId'], ['client_auth_method', 'clientAuthMethod'], ['client_auth_key_id', 'clientAuthKeyId'],
  ['dpop_jkt', 'dpopJkt'], ['oauth_scope', 'oauthScope'], ['access_jti', 'accessJti'], ['revoked_at', 'revokedAt'],
] as const;
const SESSION_COLUMNS = [
  ['id', 'id'], ['did', 'did'], ['client_id', 'clientId'], ['client_auth_method', 'clientAuthMethod'],
  ['client_auth_key_id', 'clientAuthKeyId'], ['client_auth_key_binding', 'clientAuthKeyBinding'],
  ['dpop_jkt', 'dpopJkt'], ['scope', 'scope'], ['current_refresh_token_id', 'currentRefreshTokenId'],
  ['access_jti', 'accessJti'], ['created_at', 'createdAt'], ['updated_at', 'updatedAt'],
  ['expires_at', 'expiresAt'], ['revoked_at', 'revokedAt'],
] as const;

type Column = readonly [string, string];
type SqlValue = string | number | null;
const numeric = new Set(['expires_at', 'created_at', 'updated_at', 'revoked_at']);
const nullable = new Set(['app_password_name', 'next_id', 'client_auth_key_id', 'client_auth_key_binding', 'revoked_at']);

function selectFields(alias: string, columns: readonly Column[], prefix: string): string {
  return columns.map(([column, property]) => `${alias}.${column} AS "${prefix}${property}"`).join(', ');
}

function validFields(alias: string, columns: readonly Column[]): string[] {
  return columns.map(([column]) => {
    const value = `${alias}.${column}`;
    const valid = numeric.has(column)
      ? `typeof(${value}) = 'integer' AND ${value} BETWEEN 0 AND ${MAX_INTEGER}`
      : `typeof(${value}) = 'text' AND length(CAST(${value} AS BLOB)) BETWEEN 1 AND ${TEXT_LIMIT}`;
    return nullable.has(column) ? `(${value} IS NULL OR (${valid}))` : `(${valid})`;
  });
}

function textSize(alias: string, columns: readonly Column[]): string[] {
  return columns.filter(([column]) => !numeric.has(column))
    .map(([column]) => `COALESCE(length(CAST(${alias}.${column} AS BLOB)), 0)`);
}

const READ_SNAPSHOT = `SELECT ${selectFields('r', REFRESH_COLUMNS, 'r_')},
  ${selectFields('s', SESSION_COLUMNS, 's_')}
  FROM refresh_token r JOIN oauth_session s ON s.id = r.oauth_session_id
  WHERE r.id = ? AND ${[...validFields('r', REFRESH_COLUMNS), ...validFields('s', SESSION_COLUMNS)].join(' AND ')}
    AND (${[...textSize('r', REFRESH_COLUMNS), ...textSize('s', SESSION_COLUMNS)].join(' + ')}) <= ${TEXT_LIMIT}`;
const READ_SESSION = `SELECT ${selectFields('s', SESSION_COLUMNS, 's_')} FROM oauth_session s
  WHERE s.id = ? AND ${validFields('s', SESSION_COLUMNS).join(' AND ')}
    AND (${textSize('s', SESSION_COLUMNS).join(' + ')}) <= ${TEXT_LIMIT}`;

function extract(row: Record<string, SqlValue>, prefix: string, columns: readonly Column[]): Record<string, SqlValue> {
  return Object.fromEntries(columns.map(([, property]) => [property, row[`${prefix}${property}`]]));
}

/** Load both rows in one primary-D1 read without transferring oversized fields. */
export async function loadOAuthRefreshSnapshot(
  env: Env,
  id: string,
): Promise<{ readonly refresh: RefreshTokenRow; readonly session: OAuthSessionRow } | null> {
  if (!id || id.length > 8192 || new TextEncoder().encode(id).byteLength > 8192) return null;
  const row = await env.ALTERAN_DB.prepare(READ_SNAPSHOT).bind(id).first<Record<string, SqlValue>>();
  if (!row) return null;
  return {
    refresh: extract(row, 'r_', REFRESH_COLUMNS) as RefreshTokenRow,
    session: extract(row, 's_', SESSION_COLUMNS) as OAuthSessionRow,
  };
}

export async function loadOAuthSessionSnapshot(env: Env, id: string): Promise<OAuthSessionRow | null> {
  if (!id || id.length > 8192 || new TextEncoder().encode(id).byteLength > 8192) return null;
  const row = await env.ALTERAN_DB.prepare(READ_SESSION).bind(id).first<Record<string, SqlValue>>();
  return row ? extract(row, 's_', SESSION_COLUMNS) as OAuthSessionRow : null;
}

export function refreshSnapshotWhere(alias: string): string {
  return REFRESH_COLUMNS.map(([column]) => `${alias}.${column} IS ?`).join(' AND ');
}

export function sessionSnapshotWhere(alias: string): string {
  return SESSION_COLUMNS.map(([column]) => `${alias}.${column} IS ?`).join(' AND ');
}

export function refreshSnapshotValues(row: RefreshTokenRow): SqlValue[] {
  return REFRESH_COLUMNS.map(([, property]) => row[property as keyof RefreshTokenRow]);
}

export function sessionSnapshotValues(row: OAuthSessionRow): SqlValue[] {
  return SESSION_COLUMNS.map(([, property]) => row[property as keyof OAuthSessionRow]);
}

export function oauthRefreshSnapshotFits(refresh: RefreshTokenRow, session: OAuthSessionRow): boolean {
  const encoder = new TextEncoder();
  let total = 0;
  for (const value of [...refreshSnapshotValues(refresh), ...sessionSnapshotValues(session)]) {
    if (typeof value !== 'string') continue;
    if (value.length > TEXT_LIMIT) return false;
    total += encoder.encode(value).byteLength;
    if (total > TEXT_LIMIT) return false;
  }
  return true;
}
