import { describe, it } from "./helpers/bdd";
import { expect } from "@std/expect";
import { makeEnv } from './helpers/env';
import * as Create from '../src/pages/xrpc/com.atproto.repo.createRecord';
import { issueSessionTokens } from '../src/lib/session-tokens';

describe('JSON size limit enforcement', () => {
  it('rejects oversized JSON bodies with 413', async () => {
    const env = await makeEnv({ PDS_MAX_JSON_BYTES: '128' });

    // Real access token: the bounded-read happens after auth, and the auth
    // path no longer honors a dev-token shortcut.
    const { accessJwt } = await issueSessionTokens(env, env.PDS_DID as string);

    const bigText = 'x'.repeat(1024);
    const body = JSON.stringify({ collection: 'app.bsky.feed.post', record: { text: bigText } });
    const req = new Request('http://localhost/xrpc/com.atproto.repo.createRecord', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${accessJwt}`,
      },
      body,
    });
    const res = await (Create.POST as unknown as (ctx: {
      locals: { runtime: { env: typeof env } };
      request: Request;
    }) => Promise<Response>)({
      locals: { runtime: { env } },
      request: req,
    });
    expect(res.status).toBe(413);
  });
});

