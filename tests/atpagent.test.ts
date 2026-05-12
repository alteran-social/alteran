// This suite imports the Astro-built app via createApp(), which transitively
// pulls in '@astrojs-manifest' — a virtual module that only exists inside the
// built worker. Running it under plain `bun test` fails at import time.
// Gate behind RUN_APP_TESTS=true to match tests/app.test.ts.
import { describe, it, expect, beforeAll } from 'bun:test';

const runAppIntegrationTests = process.env.RUN_APP_TESTS === 'true';
const describeIntegration = runAppIntegrationTests ? describe : describe.skip;

import { createApp } from '../src/app';
import { makeEnv, ctx } from './helpers/env';
import { AtpAgent } from '@atproto/api';
import { ensureChatTables } from '../src/lib/chat';

const app = runAppIntegrationTests ? createApp() : (null as unknown as ReturnType<typeof createApp>);

function makeFetch(env: Awaited<ReturnType<typeof makeEnv>>) {
  return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = typeof input === 'string' ? new URL(input, 'http://localhost') : (input instanceof URL ? input : new URL(input.url));
    const req = input instanceof Request ? input : new Request(url.toString(), init);
    return app.fetch(req, env as any, ctx);
  };
}

describeIntegration('AtpAgent integration', () => {
  let env: Awaited<ReturnType<typeof makeEnv>>;
  let fetchImpl: ReturnType<typeof makeFetch>;

  beforeAll(async () => {
    env = await makeEnv();
    fetchImpl = makeFetch(env);
    // Bootstrap DB
    await app.fetch(new Request('http://localhost/debug/db/bootstrap', { method: 'POST' }), env, ctx);
  });

  it('login and create/get record via AtpAgent', async () => {
    const agent = new AtpAgent({ service: 'http://localhost', fetch: fetchImpl as any });
    // login
    await agent.login({ identifier: 'user', password: 'pwd' });
    expect(agent.session?.accessJwt).toBeDefined();
    const did = String(env.PDS_DID);
    // create record
    const createRes = await agent.com.atproto.repo.createRecord({
      repo: did,
      collection: 'app.bsky.feed.post',
      record: { text: 'from agent' },
    });
    expect(createRes.success).toBe(true);
    const uri = (createRes.data as any).uri as string;
    expect(uri.startsWith(`at://${did}/app.bsky.feed.post/`)).toBe(true);
    // get record
    const getRes = await agent.com.atproto.repo.getRecord({ repo: did, collection: 'app.bsky.feed.post', rkey: uri.split('/').pop()! });
    expect(getRes.success).toBe(true);
  });

  it('subscribeRepos supports cursor replay', async () => {
    // Build a local URL using the test app
    const base = 'http://localhost';
    // connect WS without cursor
    const url = base.replace('http', 'ws') + '/xrpc/com.atproto.sync.subscribeRepos';
    const ws1 = new WebSocket(url);
    const events1: any[] = [];
    ws1.addEventListener('message', (e) => { try { events1.push(JSON.parse(String((e as MessageEvent).data))); } catch {} });
    await new Promise((r) => ws1.addEventListener('open', () => r(undefined)));
    // produce a couple commits via writes
    const sess = (await fetch(base + '/xrpc/com.atproto.server.createSession', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ identifier: 'ws', password: 'changeme' }),
    }).then((r) => r.json())) as { accessJwt?: string };
    if (typeof sess.accessJwt !== 'string') throw new Error('session response missing accessJwt');
    const auth = { authorization: `Bearer ${sess.accessJwt}` };
    for (let i = 0; i < 2; i++) {
      await fetch(base + '/xrpc/com.atproto.repo.createRecord', { method: 'POST', headers: { 'content-type': 'application/json', ...auth }, body: JSON.stringify({ collection: 'app.bsky.feed.post', record: { text: `ws-${i}` } }) });
    }
    await new Promise((r) => setTimeout(r, 200));
    ws1.close();

    // Find last seq from events1
    const commits = events1.filter((e) => e.type === 'commit');
    const last = commits[commits.length - 1];
    const cursor = last?.seq ?? 0;

    // connect with cursor to replay future ones
    const ws2 = new WebSocket(url + `?cursor=${cursor}`);
    const events2: any[] = [];
    ws2.addEventListener('message', (e) => { try { events2.push(JSON.parse(String((e as MessageEvent).data))); } catch {} });
    await new Promise((r) => ws2.addEventListener('open', () => r(undefined)));
    // create more commits
    for (let i = 0; i < 2; i++) {
      await fetch(base + '/xrpc/com.atproto.repo.createRecord', { method: 'POST', headers: { 'content-type': 'application/json', ...auth }, body: JSON.stringify({ collection: 'app.bsky.feed.post', record: { text: `ws2-${i}` } }) });
    }
    await new Promise((r) => setTimeout(r, 200));
    ws2.close();
    const commits2 = events2.filter((e) => e.type === 'commit');
    expect(commits2.length).toBeGreaterThan(0);
    // ensure seqs are strictly greater than cursor
    expect(Math.min(...commits2.map((c) => c.seq))).toBeGreaterThan(cursor);
  });

  it('serves app.bsky actor/feed/notification endpoints', async () => {
    const agent = new AtpAgent({ service: 'http://localhost', fetch: fetchImpl as any });
    await agent.login({ identifier: 'user', password: 'pwd' });
    const did = String(env.PDS_DID);

    // ensure data exists in repo
    const post = await agent.com.atproto.repo.createRecord({
      repo: did,
      collection: 'app.bsky.feed.post',
      record: { text: 'timeline hello' },
    });
    expect(post.success).toBe(true);

    const labelerRecord = await agent.com.atproto.repo.putRecord({
      repo: did,
      collection: 'app.bsky.labeler.service',
      rkey: 'self',
      record: {
        $type: 'app.bsky.labeler.service',
        createdAt: new Date().toISOString(),
        policies: {
          labelValues: ['!warn'],
        },
      },
    } as any);
    expect(labelerRecord.success).toBe(true);

    const profile = await agent.app.bsky.actor.getProfile({ actor: did });
    expect(profile.success).toBe(true);
    expect(profile.data.did).toBe(did);

    const profiles = await agent.app.bsky.actor.getProfiles({ actors: [did] });
    expect(profiles.success).toBe(true);
    expect(profiles.data.profiles.length).toBeGreaterThan(0);

    const prefsBefore = await agent.app.bsky.actor.getPreferences();
    expect(prefsBefore.success).toBe(true);

    const savePrefs = await agent.app.bsky.actor.putPreferences({
      preferences: [
        {
          $type: 'app.bsky.actor.defs#savedFeedsPref',
          saved: [],
          pinned: [],
        },
      ],
    } as any);
    expect(savePrefs.success).toBe(true);

    const timeline = await agent.app.bsky.feed.getTimeline();
    expect(timeline.success).toBe(true);

    const authorFeed = await agent.app.bsky.feed.getAuthorFeed({ actor: did });
    expect(authorFeed.success).toBe(true);

    const posts = await agent.app.bsky.feed.getPosts({ uris: [post.data.uri] });
    expect(posts.success).toBe(true);
    expect(posts.data.posts[0]?.uri).toBe(post.data.uri);

    const thread = await agent.app.bsky.feed.getPostThread({ uri: post.data.uri });
    expect(thread.success).toBe(true);

    const followers = await agent.app.bsky.graph.getFollowers({ actor: did });
    expect(followers.success).toBe(true);

    const follows = await agent.app.bsky.graph.getFollows({ actor: did });
    expect(follows.success).toBe(true);

    const notifications = await agent.app.bsky.notification.listNotifications();
    expect(notifications.success).toBe(true);

    const unread = await agent.app.bsky.notification.getUnreadCount();
    expect(unread.success).toBe(true);
    expect(unread.data.count).toBe(0);

    const config = await agent.app.bsky.unspecced.getConfig();
    expect(config.success).toBe(true);

    const aaState = await agent.app.bsky.unspecced.getAgeAssuranceState();
    expect(aaState.success).toBe(true);

    const labelerViews = await agent.app.bsky.labeler.getServices({ dids: [did], detailed: true });
    expect(labelerViews.success).toBe(true);
    expect(labelerViews.data.views.length).toBeGreaterThan(0);

    await ensureChatTables(env as any);
    await env.ALTERAN_DB.exec('DELETE FROM chat_convo_member; DELETE FROM chat_convo;');

    const now = Date.now();
    const lastMessage = {
      id: 'msg1',
      rev: '0',
      text: 'Hi there',
      sender: { did },
      sentAt: new Date(now).toISOString(),
      reactions: [],
      facets: [],
    };

    await env.ALTERAN_DB.prepare(
      'INSERT INTO chat_convo (id, rev, status, muted, unread_count, last_message_json, last_reaction_json, updated_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
    )
      .bind('convo-test', '0', 'accepted', 0, 1, JSON.stringify(lastMessage), null, now, now)
      .run();

    await env.ALTERAN_DB.prepare(
      'INSERT OR REPLACE INTO chat_convo_member (convo_id, did, handle, display_name, avatar, position) VALUES (?, ?, ?, ?, ?, ?)',
    )
      .bind('convo-test', did, String(env.PDS_HANDLE ?? 'user.example.com'), 'Owner', null, 0)
      .run();

    await env.ALTERAN_DB.prepare(
      'INSERT OR REPLACE INTO chat_convo_member (convo_id, did, handle, display_name, avatar, position) VALUES (?, ?, ?, ?, ?, ?)',
    )
      .bind('convo-test', 'did:example:friend', 'friend.test', 'Friend', null, 1)
      .run();

    const convos = await agent.chat.bsky.convo.listConvos({ limit: 20 });
    expect(convos.success).toBe(true);
    expect(convos.data.convos.length).toBeGreaterThan(0);

    const convoLog = await agent.chat.bsky.convo.getLog({});
    expect(convoLog.success).toBe(true);
    expect(Array.isArray(convoLog.data.logs)).toBe(true);
    expect(convoLog.data.logs.length).toBeGreaterThan(0);
  });
});
