import type { Env } from '../env';

let tablesEnsured = false;

export interface ListConvosFilters {
  readState?: 'unread' | null;
  status?: 'request' | 'accepted' | null;
}

export interface ConvoView {
  id: string;
  rev: string;
  members: unknown[];
  muted: boolean;
  unreadCount: number;
  status?: string;
  lastMessage?: unknown;
  lastReaction?: unknown;
}

export type ConvoLogEntry =
  | { $type: 'chat.bsky.convo.defs#logBeginConvo'; rev: string; convoId: string }
  | { $type: 'chat.bsky.convo.defs#logCreateMessage'; rev: string; convoId: string; message: unknown }
  | {
      $type: 'chat.bsky.convo.defs#logAddReaction';
      rev: string;
      convoId: string;
      message: unknown;
      reaction: unknown;
    };

export async function ensureChatTables(env: Env) {
  if (tablesEnsured) return;

  // Create chat_convo table
  await env.DB.prepare(
    'CREATE TABLE IF NOT EXISTS chat_convo (' +
    'id TEXT PRIMARY KEY, ' +
    'rev TEXT NOT NULL, ' +
    'status TEXT NOT NULL DEFAULT \'accepted\', ' +
    'muted INTEGER NOT NULL DEFAULT 0, ' +
    'unread_count INTEGER NOT NULL DEFAULT 0, ' +
    'last_message_json TEXT, ' +
    'last_reaction_json TEXT, ' +
    'updated_at INTEGER NOT NULL, ' +
    'created_at INTEGER NOT NULL' +
    ')'
  ).run();

  // Create chat_convo_member table
  await env.DB.prepare(
    'CREATE TABLE IF NOT EXISTS chat_convo_member (' +
    'convo_id TEXT NOT NULL, ' +
    'did TEXT NOT NULL, ' +
    'handle TEXT NOT NULL, ' +
    'display_name TEXT, ' +
    'avatar TEXT, ' +
    'position INTEGER NOT NULL DEFAULT 0, ' +
    'PRIMARY KEY (convo_id, did)' +
    ')'
  ).run();

  // Create index
  await env.DB.prepare(
    'CREATE INDEX IF NOT EXISTS chat_convo_member_did_idx ON chat_convo_member (did)'
  ).run();

  tablesEnsured = true;
}

export async function listChatConvos(
  env: Env,
  did: string,
  limit: number,
  cursor?: number,
  filters: ListConvosFilters = {}
) {
  await ensureChatTables(env);

  const params: (string | number)[] = [did];
  let query = `
    SELECT rowid, id, rev, status, muted, unread_count, last_message_json, last_reaction_json, updated_at
    FROM chat_convo
    WHERE EXISTS (
      SELECT 1 FROM chat_convo_member m WHERE m.convo_id = chat_convo.id AND m.did = ?
    )
  `;

  if (filters.readState === 'unread') {
    query += ' AND unread_count > 0';
  }

  if (filters.status === 'request' || filters.status === 'accepted') {
    query += ' AND status = ?';
    params.push(filters.status);
  }

  if (typeof cursor === 'number' && Number.isFinite(cursor)) {
    query += ' AND rowid < ?';
    params.push(cursor);
  }

  query += ' ORDER BY rowid DESC LIMIT ?';
  params.push(limit);

  const result = await env.DB.prepare(query).bind(...params).all<{
    rowid: number;
    id: string;
    rev: string;
    status: string;
    muted: number;
    unread_count: number;
    last_message_json: string | null;
    last_reaction_json: string | null;
    updated_at: number;
  }>();

  const convos: ConvoView[] = [];

  if (result.results) {
    for (const row of result.results) {
      const members = await env.DB.prepare(
        `SELECT did, handle, display_name, avatar FROM chat_convo_member WHERE convo_id = ? ORDER BY position ASC`
      )
        .bind(row.id)
        .all<{
          did: string;
          handle: string;
          display_name: string | null;
          avatar: string | null;
        }>();

      type MemberView = {
        did: string;
        handle: string;
        displayName?: string;
        avatar?: string;
      };
      const memberViews: MemberView[] = (members.results ?? []).map((member) => {
        const view: MemberView = {
          did: member.did,
          handle: member.handle,
        };
        if (member.display_name) view.displayName = member.display_name;
        if (member.avatar) view.avatar = member.avatar;
        return view;
      });

      convos.push({
        id: row.id,
        rev: row.rev,
        members: memberViews,
        muted: Boolean(row.muted),
        status: row.status,
        unreadCount: row.unread_count,
        lastMessage: parseMaybeJson(row.last_message_json),
        lastReaction: parseMaybeJson(row.last_reaction_json),
      });
    }
  }

  const nextCursor = result.results && result.results.length === limit
    ? String(result.results[result.results.length - 1].rowid)
    : undefined;

  return { convos, cursor: nextCursor };
}

export async function listChatConvoLogs(env: Env, did: string, cursor?: number, limit = 50) {
  await ensureChatTables(env);

  const params: (string | number)[] = [did];
  let query = `
    SELECT rowid, id, rev, last_message_json, last_reaction_json
    FROM chat_convo
    WHERE EXISTS (
      SELECT 1 FROM chat_convo_member m WHERE m.convo_id = chat_convo.id AND m.did = ?
    )
  `;

  if (typeof cursor === 'number' && Number.isFinite(cursor)) {
    query += ' AND rowid < ?';
    params.push(cursor);
  }

  query += ' ORDER BY rowid DESC LIMIT ?';
  params.push(limit);

  const result = await env.DB.prepare(query).bind(...params).all<{
    rowid: number;
    id: string;
    rev: string;
    last_message_json: string | null;
    last_reaction_json: string | null;
  }>();

  const logs: ConvoLogEntry[] = [];

  if (result.results) {
    for (const row of result.results) {
      logs.push({
        $type: 'chat.bsky.convo.defs#logBeginConvo',
        rev: row.rev,
        convoId: row.id,
      });

      const message = parseMaybeJson(row.last_message_json);
      if (message) {
        logs.push({
          $type: 'chat.bsky.convo.defs#logCreateMessage',
          rev: row.rev,
          convoId: row.id,
          message,
        });

        const reaction = parseMaybeJson(row.last_reaction_json);
        if (reaction) {
          logs.push({
            $type: 'chat.bsky.convo.defs#logAddReaction',
            rev: row.rev,
            convoId: row.id,
            message,
            reaction,
          });
        }
      }
    }
  }

  const nextCursor = result.results && result.results.length === limit
    ? String(result.results[result.results.length - 1].rowid)
    : undefined;

  return { logs, cursor: nextCursor };
}

function parseMaybeJson(input: string | null) {
  if (!input) return undefined;
  try {
    return JSON.parse(input);
  } catch {
    return undefined;
  }
}
