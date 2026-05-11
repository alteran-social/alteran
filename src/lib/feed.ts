import type { Env } from '../env';
import { getPrimaryActor, buildProfileViewBasic } from './actor';

interface PostRow {
  rowid: number;
  uri: string;
  cid: string;
  json: string;
}

interface ParsedPost {
  uri: string;
  cid: string;
  record: Record<string, unknown>;
  indexedAt: string;
  rowid: number;
}

const POST_COLLECTION = 'app.bsky.feed.post';

function inferCollectionFromUri(uri: string): string | undefined {
  if (!uri.startsWith('at://')) return undefined;
  const withoutScheme = uri.slice('at://'.length);
  const parts = withoutScheme.split('/');
  return parts.length >= 2 ? parts[1] : undefined;
}

function parseRow(row: PostRow): ParsedPost | null {
  try {
    const record = JSON.parse(row.json) ?? {};
    if (record && typeof record === 'object' && !Array.isArray(record)) {
      const collection = inferCollectionFromUri(row.uri);
      const writable = record as Record<string, unknown>;
      if (collection && typeof writable.$type !== 'string') {
        writable.$type = collection;
      }
      if (typeof writable.createdAt !== 'string') {
        writable.createdAt = new Date().toISOString();
      }
    }

    const createdAtField = (record as Record<string, unknown>).createdAt;
    const createdAt = typeof createdAtField === 'string' ? createdAtField : new Date().toISOString();

    return {
      uri: row.uri,
      cid: row.cid,
      record: record as Record<string, unknown>,
      indexedAt: createdAt,
      rowid: row.rowid,
    };
  } catch {
    return null;
  }
}

export async function listPosts(env: Env, limit: number, cursor?: string): Promise<ParsedPost[]> {
  const did = (await getPrimaryActor(env)).did;
  const safeLimit = Math.max(1, Math.min(limit || 50, 100));
  const cursorRow = cursor ? Number.parseInt(cursor, 10) : undefined;

  // Use range query instead of LIKE to avoid D1 complexity limits
  const prefix = `at://${did}/${POST_COLLECTION}/`;
  const upperBound = `${prefix}{`; // '{' sorts after 'z', safely bounding rkeys

  const params: (string | number)[] = [prefix, upperBound];
  let where = 'uri >= ? AND uri < ?';
  if (cursorRow && Number.isFinite(cursorRow)) {
    where += ' AND rowid < ?';
    params.push(cursorRow);
  }
  params.push(safeLimit);

  const response = await env.DB.prepare(
    `SELECT rowid, uri, cid, json FROM record WHERE ${where} ORDER BY rowid DESC LIMIT ?`
  )
    .bind(...params)
    .all<PostRow>();

  if (!response?.results) return [];
  return response.results.map(parseRow).filter((row): row is ParsedPost => row !== null);
}

export async function getPostsByUris(env: Env, uris: string[]): Promise<ParsedPost[]> {
  if (!uris.length) return [];
  const placeholders = uris.map(() => '?').join(',');
  const response = await env.DB.prepare(
    `SELECT rowid, uri, cid, json FROM record WHERE uri IN (${placeholders})`
  )
    .bind(...uris)
    .all<PostRow>();

  if (!response?.results) return [];
  return response.results.map(parseRow).filter((row): row is ParsedPost => row !== null);
}

export async function buildFeedViewPosts(env: Env, posts: ParsedPost[]) {
  const actor = await getPrimaryActor(env);
  const authorView = buildProfileViewBasic(actor);
  return posts.map((post) => ({
    $type: 'app.bsky.feed.defs#feedViewPost',
    post: buildPostViewFromParsed(authorView, post),
  }));
}

function buildPostViewFromParsed(
  authorView: ReturnType<typeof buildProfileViewBasic>,
  post: ParsedPost,
) {
  return {
    $type: 'app.bsky.feed.defs#postView',
    uri: post.uri,
    cid: post.cid,
    author: authorView,
    record: post.record,
    indexedAt: post.indexedAt,
    likeCount: 0,
    repostCount: 0,
    replyCount: 0,
    quoteCount: 0,
    bookmarkCount: 0,
    viewer: { $type: 'app.bsky.feed.defs#viewerState' },
  };
}

export async function buildPostViews(env: Env, posts: ParsedPost[]) {
  const actor = await getPrimaryActor(env);
  const authorView = buildProfileViewBasic(actor);
  return posts.map((post) => buildPostViewFromParsed(authorView, post));
}

export async function buildThreadView(env: Env, root: ParsedPost) {
  const [post] = await buildPostViews(env, [root]);
  return {
    $type: 'app.bsky.feed.defs#threadViewPost',
    post,
    replies: [],
  };
}

export async function countPosts(env: Env): Promise<number> {
  const actor = await getPrimaryActor(env);
  const prefix = `at://${actor.did}/${POST_COLLECTION}/`;
  const upperBound = `${prefix}{`; // '{' sorts after 'z', safely bounding rkeys
  const response = await env.DB.prepare(
    'SELECT COUNT(*) as count FROM record WHERE uri >= ? AND uri < ?'
  )
    .bind(prefix, upperBound)
    .first<{ count: number }>();
  return response?.count ?? 0;
}

export async function getPostByUri(env: Env, uri: string): Promise<ParsedPost | null> {
  const response = await env.DB.prepare(
    'SELECT rowid, uri, cid, json FROM record WHERE uri = ? LIMIT 1'
  )
    .bind(uri)
    .first<PostRow>();

  if (!response) return null;
  return parseRow(response);
}

export type { ParsedPost };
