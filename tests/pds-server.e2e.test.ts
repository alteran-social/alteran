/**
 * PDS server integration tests copied from bluesky-social/atproto packages/pds/tests/server.test.ts
 * Adapted to run against our Astro-powered PDS so we can validate xrpc endpoints end-to-end.
 */

import { describe, it, beforeAll, afterAll } from "./helpers/bdd";
import { expect } from "@std/expect";
import { randomBytes } from 'node:crypto';
import { Buffer } from 'node:buffer';
import type { AstroTestServer } from './helpers/astro-server';
import { startAstroDev, stopAstroDev } from './helpers/astro-server';

// E2E suite boots a real `astro dev` process; gate behind RUN_APP_TESTS=true
// to match tests/app.test.ts. Without the gate, beforeAll times out at 5s
// before the dev server is ready and pollutes the deno-test output.
const runAppIntegrationTests = process.env.RUN_APP_TESTS === 'true';
const describeE2E = runAppIntegrationTests ? describe : describe.skip;

process.env.PDS_SERVICE_SIGNING_KEY_HEX = process.env.PDS_SERVICE_SIGNING_KEY_HEX ?? '8b5e3d226b44c4c88fbd3d4529f6283fb2b20f6deee8a0b34e7f0a9b12d3e4f1';

let server: AstroTestServer | undefined;
let baseUrl: string;
let accessJwt: string;
let did: string;

function authHeaders() {
  return { Authorization: `Bearer ${accessJwt}` };
}

async function parseJson(res: Response) {
  const text = await res.text();
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

async function createPostRecord(extra: Record<string, unknown> = {}) {
  const record = {
    $type: 'app.bsky.feed.post',
    text: `hello-${randomBytes(4).toString('hex')}`,
    createdAt: new Date().toISOString(),
    ...extra,
  };

  const res = await fetch(`${baseUrl}/xrpc/com.atproto.repo.createRecord`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      ...authHeaders(),
    },
    body: JSON.stringify({
      repo: did,
      collection: 'app.bsky.feed.post',
      record,
    }),
  });

  const body = await parseJson(res);
  if (!res.ok) {
    throw new Error(`createRecord failed: ${JSON.stringify(body)}`);
  }

  const uri = body.uri as string;
  const rkey = uri.split('/').pop()!;
  return { uri, rkey };
}

beforeAll(async () => {
  if (!runAppIntegrationTests) return;
  server = await startAstroDev();
  baseUrl = server.url;

  const sessionRes = await fetch(
    `${baseUrl}/xrpc/com.atproto.server.createSession`,
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ identifier: 'test', password: 'pwd' }),
    },
  );

  const sessionBody = await parseJson(sessionRes);
  if (!sessionRes.ok) {
    throw new Error(`createSession failed: ${JSON.stringify(sessionBody)}`);
  }

  accessJwt = sessionBody.accessJwt as string;
  did = sessionBody.did as string;

  // Ensure repo has at least one record for sync endpoints
  await createPostRecord();
});

afterAll(async () => {
  if (server) {
    await stopAstroDev(server);
  }
});

describeE2E('PDS server parity', () => {
  it('returns 404 for unknown routes', async () => {
    const res = await fetch(`${baseUrl}/definitely-not-real`);
    expect(res.status).toBe(404);
  });

  it('rejects oversized JSON payloads', async () => {
    const res = await fetch(`${baseUrl}/xrpc/com.atproto.repo.createRecord`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...authHeaders(),
      },
      body: '"' + 'x'.repeat(150 * 1024) + '"',
    });

    expect(res.status).toBe(413);
    const body = await parseJson(res);
    expect(body).toEqual({
      error: 'PayloadTooLargeError',
      message: 'request entity too large',
    });
  });

  it('gzip compresses large JSON responses', async () => {
    const extraFields: Record<string, unknown> = {};
    for (let i = 0; i < 120; i++) {
      extraFields[`extra_${i}`] = randomBytes(16).toString('hex');
    }

    const { rkey } = await createPostRecord(extraFields);

    const res = await fetch(
      `${baseUrl}/xrpc/com.atproto.repo.getRecord?repo=${encodeURIComponent(
        did,
      )}&collection=app.bsky.feed.post&rkey=${encodeURIComponent(rkey)}`,
      {
        headers: {
          ...authHeaders(),
          'accept-encoding': 'gzip',
        },
      },
    );

    expect(res.status).toBe(200);
    await res.arrayBuffer();
    expect(res.headers.get('content-encoding')).toBe('gzip');
  });

  it('gzip compresses repo CAR responses', async () => {
    const res = await fetch(
      `${baseUrl}/xrpc/com.atproto.sync.getRepo?did=${encodeURIComponent(did)}`,
      {
        headers: { 'accept-encoding': 'gzip' },
      },
    );

    expect(res.status).toBe(200);
    await res.arrayBuffer();
    expect(res.headers.get('content-encoding')).toBe('gzip');
  });

  it('acknowledges PLC request-token invocation', async () => {
    const res = await fetch(
      `${baseUrl}/xrpc/com.atproto.identity.requestPlcOperationSignature`,
      {
        method: 'POST',
        headers: {
          ...authHeaders(),
        },
      },
    );

    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).toBe('');
  });

  it('issues service auth tokens', async () => {
    const params = new URLSearchParams({
      aud: 'did:web:bsky.social',
      lxm: 'com.atproto.server.createAccount',
    });

    const res = await fetch(
      `${baseUrl}/xrpc/com.atproto.server.getServiceAuth?${params.toString()}`,
      {
        headers: {
          ...authHeaders(),
        },
      },
    );

    expect(res.status).toBe(200);
    const { token } = (await parseJson(res)) as { token: string };
    expect(typeof token).toBe('string');
    const segments = token.split('.');
    expect(segments).toHaveLength(3);

    const payload = JSON.parse(Buffer.from(segments[1], 'base64url').toString());
    expect(payload.iss).toBe(did);
    expect(payload.aud).toBe('did:web:bsky.social');
    expect(payload.lxm).toBe('com.atproto.server.createAccount');
  });
});
