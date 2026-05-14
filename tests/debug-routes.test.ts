import { describe, it } from "./helpers/bdd";
import { expect } from "@std/expect";
import { makeEnv } from './helpers/env';
import * as DebugRecord from '../src/pages/debug/record';
import * as DebugBlobGc from '../src/pages/debug/gc/blobs';

function ctx(env: Awaited<ReturnType<typeof makeEnv>>, request: Request) {
  return { locals: { runtime: { env } }, request } as any;
}

describe('debug routes', () => {
  it('does not expose mutation routes in production', async () => {
    const env = await makeEnv({
      ENVIRONMENT: 'production',
      PDS_HOSTNAME: 'pds.example',
    });

    const recordPost = await DebugRecord.POST(ctx(env, new Request('https://pds.example/debug/record', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        uri: 'at://did:example:test/app.bsky.feed.post/debug',
        json: { text: 'blocked' },
      }),
    })));
    expect(recordPost.status).toBe(404);

    const gcPost = await DebugBlobGc.POST(ctx(env, new Request('https://pds.example/debug/gc/blobs', {
      method: 'POST',
    })));
    expect(gcPost.status).toBe(404);
  });
});
