import { describe, it } from "./helpers/bdd";
import { expect } from "@std/expect";
import { makeEnv } from './helpers/env';
import * as DebugRecord from '../src/pages/debug/record';
import * as DebugBlobGc from '../src/pages/debug/gc/blobs';
import alteran from '../index.js';

function ctx(env: Awaited<ReturnType<typeof makeEnv>>, request: Request) {
  return { locals: { env }, request } as any;
}

describe('debug routes', () => {
  it('does not expose arbitrary blob keys through Astro route injection or file routing', async () => {
    const patterns: string[] = [];
    alteran({ debugRoutes: true }).hooks['astro:config:setup']({
      config: { output: 'server', root: new URL('file:///tmp/alteran-consumer/') },
      updateConfig: () => {},
      addMiddleware: () => {},
      injectRoute: (route: { pattern: string }) => patterns.push(route.pattern),
      logger: {},
    });

    expect(patterns).toContain('/debug/record');
    expect(patterns).not.toContain('/debug/blob/[...key]');
    await expect(Deno.stat('src/pages/debug/blob/[...key].ts')).rejects.toBeInstanceOf(Deno.errors.NotFound);
  });

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
