import { describe, expect, it } from 'bun:test';
import type { D1Database } from '@cloudflare/workers-types';
import { readFileSync } from 'fs';
import { join } from 'path';
import {
  GetBlob,
  WRONG_CID,
  blobBody,
  callGetRoute,
  makeEnv,
  postRecord,
  rawBlob,
} from './helpers/repo-write';

describe('blob usage migration', () => {
  it('backfills usage from typed blob objects without matching plain CID text', async () => {
    const env = await makeEnv();
    const linkBytes = new TextEncoder().encode('referenced historical blob');
    const linkBlob = await rawBlob(linkBytes);
    const slashBytes = new TextEncoder().encode('slash link historical blob');
    const slashBlob = await rawBlob(slashBytes);
    const plainBytes = new TextEncoder().encode('plain text cid blob');
    const plainBlob = await rawBlob(plainBytes);
    const linkKey = 'historical/link-image-key';
    const slashKey = 'historical/slash-image-key';
    const plainKey = 'historical/plain-cid-key';
    const uri = `at://${env.PDS_DID}/app.bsky.feed.post/3jzfcijpj2z2n`;
    const rev = '3jzfcijpj2z2p';
    const record = postRecord('migration record', {
      embed: {
        $type: 'app.bsky.embed.images',
        images: [
          { image: linkBlob.object, alt: '' },
          { image: { ...slashBlob.object, ref: { '/': slashBlob.cid } }, alt: '' },
        ],
      },
      plainCidMention: plainBlob.cid,
    });

    await env.ALTERAN_BLOBS.put(linkKey, blobBody(linkBytes), {
      httpMetadata: { contentType: linkBlob.mimeType },
    });
    await env.ALTERAN_BLOBS.put(slashKey, blobBody(slashBytes), {
      httpMetadata: { contentType: slashBlob.mimeType },
    });
    await env.ALTERAN_BLOBS.put(plainKey, blobBody(plainBytes), {
      httpMetadata: { contentType: plainBlob.mimeType },
    });
    await env.ALTERAN_DB.batch([
      env.ALTERAN_DB.prepare(
        'INSERT INTO repo_root (did, commit_cid, rev) VALUES (?, ?, ?)',
      ).bind(env.PDS_DID, WRONG_CID, rev),
      env.ALTERAN_DB.prepare(
        'INSERT INTO record (uri, did, cid, json, created_at) VALUES (?, ?, ?, ?, ?)',
      ).bind(uri, env.PDS_DID, WRONG_CID, JSON.stringify(record), 0),
      env.ALTERAN_DB.prepare(
        'INSERT INTO blob (cid, did, key, mime, size, uploaded_at) VALUES (?, ?, ?, ?, ?, ?)',
      ).bind(linkBlob.cid, env.PDS_DID, linkKey, linkBlob.mimeType, linkBlob.size, 0),
      env.ALTERAN_DB.prepare(
        'INSERT INTO blob (cid, did, key, mime, size, uploaded_at) VALUES (?, ?, ?, ?, ?, ?)',
      ).bind(slashBlob.cid, env.PDS_DID, slashKey, slashBlob.mimeType, slashBlob.size, 0),
      env.ALTERAN_DB.prepare(
        'INSERT INTO blob (cid, did, key, mime, size, uploaded_at) VALUES (?, ?, ?, ?, ?, ?)',
      ).bind(plainBlob.cid, env.PDS_DID, plainKey, plainBlob.mimeType, plainBlob.size, 0),
    ]);

    await applyBackfillMigration(env.ALTERAN_DB);

    const usage = await env.ALTERAN_DB.prepare(
      'SELECT key, cid, repo_rev FROM blob_usage WHERE did = ? ORDER BY key',
    ).bind(env.PDS_DID).all<{ key: string; cid: string; repo_rev: string }>();
    expect(usage.results).toEqual([
      { key: linkKey, cid: linkBlob.cid, repo_rev: rev },
      { key: slashKey, cid: slashBlob.cid, repo_rev: rev },
    ]);

    const getReferenced = await callGetRoute(
      GetBlob,
      env,
      `https://pds.example/xrpc/com.atproto.sync.getBlob?did=${env.PDS_DID}&cid=${linkBlob.cid}`,
    );
    expect(getReferenced.status).toBe(200);
    expect(await getReferenced.text()).toBe('referenced historical blob');

    const getSlashLink = await callGetRoute(
      GetBlob,
      env,
      `https://pds.example/xrpc/com.atproto.sync.getBlob?did=${env.PDS_DID}&cid=${slashBlob.cid}`,
    );
    expect(getSlashLink.status).toBe(200);
    expect(await getSlashLink.text()).toBe('slash link historical blob');

    const getPlainMention = await callGetRoute(
      GetBlob,
      env,
      `https://pds.example/xrpc/com.atproto.sync.getBlob?did=${env.PDS_DID}&cid=${plainBlob.cid}`,
    );
    expect(getPlainMention.status).toBe(400);
  });
});

async function applyBackfillMigration(database: D1Database): Promise<void> {
  const sql = readFileSync(
    join(import.meta.dir, '..', 'migrations', '0012_backfill_blob_usage.sql'),
    'utf8',
  );
  for (const chunk of sql.split('--> statement-breakpoint')) {
    const statement = chunk.trim();
    if (statement) await database.exec(statement.replace(/\n/g, ' '));
  }
}
