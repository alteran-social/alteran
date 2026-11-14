import { isValidDid } from '@atproto/syntax-spaces';
import { expect } from '@std/expect';
import { makeSpaceEnv as makeEnv } from './helpers/space-env';
import { applySpaceWrites, createLocalSpace, streamSpaceRepoArchive } from './helpers/space-adapters';

const configPath = Deno.env.get('ALTERAN_REFERENCE_INTEROP_CONFIG');
const COLLECTION = 'com.example.note';

Deno.test({
  name: 'reference PDS imports an Alteran streamed STAR archive',
  ignore: !configPath,
  sanitizeOps: false,
  sanitizeResources: false,
  fn: withReferenceErrors(async () => {
    if (!configPath) throw new Error('Missing reference configuration');
    const config = JSON.parse(await Deno.readTextFile(configPath)) as {
      pds: unknown; did: unknown; accessJwt: unknown;
    };
    const pds = loopbackOrigin(config.pds);
    if (!isValidDid(config.did) || typeof config.accessJwt !== 'string' || !config.accessJwt) {
      throw new Error('Invalid disposable reference account');
    }
    const repo = config.did;
    const skey = `interop-export-${crypto.randomUUID()}`;
    const space = `at://${repo}/space/${COLLECTION}/${skey}`;
    const authorization = `Bearer ${config.accessJwt}`;
    async function rpc(method: string, init: RequestInit = {}) {
      const response = await referenceRequest(pds, authorization, method, init);
      if (!response.ok) {
        await response.body?.cancel();
        throw new Error(`Reference PDS returned HTTP ${response.status}`);
      }
      return response;
    }
    const post = (method: string, body: unknown) => rpc(method, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
    });
    await withFixtureCleanup(async () => {
      await post('com.atproto.space.createSpace', {
        spaceType: COLLECTION, skey, policy: { $type: 'com.atproto.personalspace.policy' },
      });
      const env = await makeEnv({ PDS_DID: repo });
      await createLocalSpace(env, space);
      await applySpaceWrites(env, space, repo, [{
        action: 'create', collection: COLLECTION, rkey: 'note',
        record: { $type: COLLECTION, text: 'streamed from Alteran' },
      }]);
      const exportResult = await streamSpaceRepoArchive(env, space, repo);
      const bytes = await new Response(exportResult.body).arrayBuffer();
      await rpc('com.atproto.space.importRepo', {
        method: 'POST', headers: { 'Content-Type': 'application/vnd.dasl.star' }, body: bytes,
      });
      const params = new URLSearchParams({ space, repo, collection: COLLECTION, rkey: 'note' });
      const record = await (await rpc(`com.atproto.space.getRecord?${params}`)).json() as { value: unknown };
      expect(sameJson(record.value, { $type: COLLECTION, text: 'streamed from Alteran' })).toBe(true);
      const commit = await (await rpc(`com.atproto.space.getLatestCommit?${new URLSearchParams({ space, repo })}`))
        .json() as { commit: { data: { $bytes: string } } };
      const referenceDigest = Uint8Array.from(atob(commit.commit.data.$bytes), (char) => char.charCodeAt(0));
      expect(referenceDigest.length === exportResult.commit.data.length &&
        referenceDigest.every((byte, index) => byte === exportResult.commit.data[index])).toBe(true);
    }, async () => {
      await finishSpaceCleanup(await referenceRequest(pds, authorization, 'com.atproto.space.deleteSpace', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ space }),
      }));
    });
  }),
});

async function referenceRequest(pds: string, authorization: string, method: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  headers.set('Authorization', authorization);
  return await fetch(`${pds}/xrpc/${method}`, {
    ...init, headers, redirect: 'manual', signal: AbortSignal.timeout(10_000),
  });
}

async function withFixtureCleanup(action: () => Promise<void>, cleanup: () => Promise<void>): Promise<void> {
  let attempted = false;
  try {
    attempted = true;
    await action();
  } finally {
    if (attempted) await cleanup();
  }
}

async function finishSpaceCleanup(response: Response): Promise<void> {
  if (response.ok) {
    await response.body?.cancel();
    return;
  }
  if (response.status === 400) {
    const body = await response.json() as { error?: unknown };
    if (body && typeof body === 'object' && body.error === 'SpaceNotFound') return;
  } else {
    await response.body?.cancel();
  }
  throw new Error('Reference cleanup failed');
}

Deno.test('fixture cleanup runs after an attempted creation fails', async () => {
  const lostResponse = new Error('Simulated response loss');
  let cleaned = false;
  let failure: unknown;
  try {
    await withFixtureCleanup(async () => { throw lostResponse; }, async () => { cleaned = true; });
  } catch (caught) {
    failure = caught;
  }
  expect(cleaned && failure === lostResponse).toBe(true);
  await finishSpaceCleanup(new Response('{"error":"SpaceNotFound"}', { status: 400 }));
  let rejected = false;
  try {
    await finishSpaceCleanup(new Response('{"error":"OtherError"}', { status: 400 }));
  } catch {
    rejected = true;
  }
  expect(rejected).toBe(true);
});

Deno.test({
  name: 'reference cleanup handles a lost creation response and an absent Space',
  ignore: !configPath,
  fn: withReferenceErrors(async () => {
    if (!configPath) throw new Error('Missing reference configuration');
    const config = JSON.parse(await Deno.readTextFile(configPath)) as { pds: unknown; did: unknown; accessJwt: unknown };
    const pds = loopbackOrigin(config.pds);
    if (!isValidDid(config.did) || typeof config.accessJwt !== 'string' || !config.accessJwt) {
      throw new Error('Invalid disposable reference account');
    }
    const authorization = `Bearer ${config.accessJwt}`;
    const skey = `cleanup-${crypto.randomUUID()}`;
    const space = `at://${config.did}/space/${COLLECTION}/${skey}`;
    const post = (method: string, body: unknown) => referenceRequest(pds, authorization, method, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
    });
    const lostResponse = new Error('Simulated response loss');
    let failure: unknown;
    try {
      await withFixtureCleanup(async () => {
        const created = await post('com.atproto.space.createSpace', {
          spaceType: COLLECTION, skey, policy: { $type: 'com.atproto.personalspace.policy' },
        });
        if (!created.ok) throw new Error('Fixture creation failed');
        await created.body?.cancel();
        throw lostResponse;
      }, async () => await finishSpaceCleanup(await post('com.atproto.space.deleteSpace', { space })));
    } catch (caught) {
      failure = caught;
    }
    expect(failure === lostResponse).toBe(true);
    const lookup = await referenceRequest(pds, authorization, `com.atproto.space.getSpace?${new URLSearchParams({ space })}`);
    const result = await lookup.json() as { error?: unknown };
    expect(lookup.status === 400 && result.error === 'SpaceNotFound').toBe(true);
    const neverCreated = `at://${config.did}/space/${COLLECTION}/cleanup-${crypto.randomUUID()}`;
    const missing = await post('com.atproto.space.deleteSpace', { space: neverCreated });
    expect(missing.status === 400).toBe(true);
    await finishSpaceCleanup(missing);
  }),
});

function loopbackOrigin(value: unknown): string {
  if (typeof value !== 'string') throw new Error('A loopback URL is required');
  const url = new URL(value);
  if (url.protocol !== 'http:' || !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname) ||
    url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
    throw new Error('Only a loopback reference PDS origin is allowed');
  }
  return url.origin;
}


function withReferenceErrors<T>(action: () => T | Promise<T>): () => Promise<T> {
  return async () => {
    try {
      return await action();
    } catch {
      throw new Error('Reference interoperability failed');
    }
  };
}

Deno.test('reference failure output excludes private input', async () => {
  const sentinel = 'harmless-private-sentinel';
  const malformed = `{"accessJwt":${sentinel}}`;
  const path = await Deno.makeTempFile();
  try {
    await Deno.writeTextFile(path, malformed);
    const failures = [
      async () => JSON.parse(await Deno.readTextFile(path)),
      () => new URL(`http://[${sentinel}`),
      () => new Headers({ authorization: `Bearer ${sentinel}\0` }),
      () => JSON.parse(malformed),
      () => { throw new Error(`server response: ${sentinel}`); },
    ];
    for (const failure of failures) {
      let caught: unknown;
      try {
        await withReferenceErrors(failure)();
      } catch (error) {
        caught = error;
      }
      expect(caught instanceof Error && caught.message === 'Reference interoperability failed').toBe(true);
      expect(caught instanceof Error && typeof caught.stack === 'string' && !caught.stack.includes(sentinel)).toBe(true);
    }
  } finally {
    await Deno.remove(path);
  }
});

function sameJson(left: unknown, right: unknown): boolean {
  if (left === right) return true;
  if (!left || !right || typeof left !== 'object' || typeof right !== 'object' ||
    Array.isArray(left) !== Array.isArray(right)) return false;
  if (Array.isArray(left) && Array.isArray(right) && left.length !== right.length) return false;
  const leftFields = left as Record<string, unknown>;
  const rightFields = right as Record<string, unknown>;
  const keys = Object.keys(leftFields);
  return keys.length === Object.keys(rightFields).length && keys.every((key) =>
    Object.hasOwn(rightFields, key) && sameJson(leftFields[key], rightFields[key])
  );
}
