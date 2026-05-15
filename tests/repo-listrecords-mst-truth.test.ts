import { describe, it } from './helpers/bdd';
import { expect } from '@std/expect';
import { RepoManager } from '../src/services/repo-manager';
import { ApplyWrites, callRoute, json, makeEnv } from './helpers/repo-write';

// Regression for the unfollow-stuck bug: when a row exists in the `record`
// table but its key is not in the MST, `RepoManager.listRecords` and
// `RepoManager.getRecord` used to fall back to the table and return the
// orphan. The AppView then indexed those URIs, but subsequent deleteRecord
// calls silently no-op'd because deleteRecord checks the MST. The MST is the
// canonical record of repo state, so the table is never a fallback.
describe('RepoManager listRecords / getRecord ignore orphan record-table rows', () => {
  it('returns an empty list when the MST has nothing for the collection, even if the record table has rows', async () => {
    const env = await makeEnv();
    const orphanUri = `at://${env.PDS_DID}/app.bsky.graph.follow/3bbbbbbbbbbbb`;
    await env.ALTERAN_DB.prepare(
      'INSERT INTO record (uri, did, cid, json, created_at) VALUES (?, ?, ?, ?, ?)',
    )
      .bind(orphanUri, env.PDS_DID, 'bafyreigh2akiscaildc4q7fapfs3krvmxz2s5tapqyqdr6fhyjn4zpd6du', '{"$type":"app.bsky.graph.follow","subject":"did:example:other","createdAt":"2026-05-15T00:00:00.000Z"}', 0)
      .run();

    const repoManager = new RepoManager(env);
    expect(await repoManager.listRecords('app.bsky.graph.follow')).toEqual([]);
    expect(await repoManager.getRecord('app.bsky.graph.follow', '3bbbbbbbbbbbb')).toBeNull();
  });

  it('returns only real MST entries when the table additionally holds an orphan', async () => {
    const env = await makeEnv();

    const created = await callRoute(ApplyWrites, env, {
      repo: env.PDS_DID,
      writes: [
        {
          $type: 'com.atproto.repo.applyWrites#create',
          collection: 'app.bsky.graph.follow',
          rkey: '3aaaaaaaaaaaa',
          value: { $type: 'app.bsky.graph.follow', subject: 'did:example:real', createdAt: '2026-05-15T00:00:00.000Z' },
        },
      ],
    });
    expect(created.status).toBe(200);
    await json(created);

    const orphanUri = `at://${env.PDS_DID}/app.bsky.graph.follow/3bbbbbbbbbbbb`;
    await env.ALTERAN_DB.prepare(
      'INSERT INTO record (uri, did, cid, json, created_at) VALUES (?, ?, ?, ?, ?)',
    )
      .bind(orphanUri, env.PDS_DID, 'bafyreigh2akiscaildc4q7fapfs3krvmxz2s5tapqyqdr6fhyjn4zpd6du', '{"$type":"app.bsky.graph.follow","subject":"did:example:ghost","createdAt":"2026-05-15T00:00:00.000Z"}', 0)
      .run();

    const repoManager = new RepoManager(env);
    const listed = await repoManager.listRecords('app.bsky.graph.follow');
    const listedKeys = listed.map((entry) => entry.key);
    expect(listedKeys).toEqual(['3aaaaaaaaaaaa']);

    expect(await repoManager.getRecord('app.bsky.graph.follow', '3bbbbbbbbbbbb')).toBeNull();
    const realRecord = await repoManager.getRecord('app.bsky.graph.follow', '3aaaaaaaaaaaa');
    expect(realRecord).toMatchObject({ subject: 'did:example:real' });
  });
});
