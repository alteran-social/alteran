import { expect } from '@std/expect';
import { isValidDid } from '@atproto/syntax-spaces';
import { DID } from './helpers/spaces-authorized-read';
import { EMPTY, policyFixture } from './helpers/spaces-policy-read';
import { listContext, signedGenesisRequest } from './helpers/spaces-list-genesis';
import { captureRecordIdentity } from '../src/lib/spaces/record-response-input';
import { GET } from '../src/pages/xrpc/com.atproto.space.listRecords';

const configPath = Deno.env.get('ALTERAN_REFERENCE_INTEROP_CONFIG');

Deno.test({
  name: 'reference PDS agrees on fresh personal Space empty pages',
  ignore: !configPath,
  sanitizeOps: false,
  sanitizeResources: false,
  async fn() {
    await guarded(async () => {
      if (!configPath) throw new Error();
      const config = await readConfig(configPath);
      if (!config || typeof config !== 'object' || Array.isArray(config)) throw new Error();
      const fields = config as Record<string, unknown>;
      const origin = loopbackOrigin(fields.pds);
      if (!isValidDid(fields.did) || typeof fields.accessJwt !== 'string' || !fields.accessJwt) throw new Error();
      const repo = fields.did;
      const skey = `empty-list-${crypto.randomUUID()}`;
      const space = `at://${repo}/space/com.example.notes/${skey}`;
      const authorization = `Bearer ${fields.accessJwt}`;
      const rpc = (name: string, init?: RequestInit) => referenceRequest(origin, name, authorization, init);
      const post = (name: string, body: unknown) => rpc(name, {
        method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
      });
      let attempted = false;
      try {
        attempted = true;
        const created = await post('com.atproto.space.createSpace', {
          spaceType: 'com.example.notes', skey, policy: { $type: 'com.atproto.personalspace.policy' },
        });
        if (!created.ok || (await readJson(created) as { space?: unknown }).space !== space) throw new Error();
        const local = await policyFixture();
        const refCursor = captureRecordIdentity({ space, repo, collection: 'com.example.note', rkey: 'one' }).uri;
        const localCursor = captureRecordIdentity({ space: EMPTY, repo: DID, collection: 'com.example.note', rkey: 'one' }).uri;
        const cases: Record<string, string>[] = [{}, { excludeValues: 'true' }, { excludeValues: 'false', limit: '1' },
          { collection: 'com.example.note', limit: '50', cursor: refCursor }];
        for (const options of cases) {
          const params = new URLSearchParams({ space, repo, ...options });
          const reference = await rpc(`com.atproto.space.listRecords?${params}`);
          if (!reference.ok) throw new Error();
          const referenceBody = await readJson(reference);
          const query = options.cursor ? { ...options, cursor: localCursor } : options;
          const request = await signedGenesisRequest(local, { query });
          const actual = await GET(listContext(local.env, request));
          if (actual.status !== 200) throw new Error();
          const localBody = await readJson(actual);
          if (JSON.stringify(referenceBody) !== '{"records":[]}' || JSON.stringify(localBody) !== '{"records":[]}') throw new Error();
        }
      } finally {
        if (attempted) {
          const deleted = await post('com.atproto.space.deleteSpace', { space });
          if (deleted.ok) await deleted.body?.cancel();
          else if (deleted.status !== 400 || (await readJson(deleted) as { error?: unknown }).error !== 'SpaceNotFound') {
            throw new Error();
          }
        }
      }
    });
  },
});

async function guarded(fn: () => Promise<void>): Promise<void> {
  try { await fn(); } catch { throw new Error('Reference genesis-list verification failed'); }
}

async function readConfig(path: string): Promise<unknown> {
  return JSON.parse(await Deno.readTextFile(path));
}

function loopbackOrigin(value: unknown): string {
  if (typeof value !== 'string') throw new Error();
  const url = new URL(value);
  if (url.protocol !== 'http:' || !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname) ||
    url.username || url.password || url.pathname !== '/' || url.search || url.hash) throw new Error();
  return url.origin;
}

async function referenceRequest(origin: string, name: string, authorization: string, init: RequestInit = {}) {
  const headers = new Headers(init.headers);
  headers.set('authorization', authorization);
  return await fetch(`${origin}/xrpc/${name}`, {
    ...init, headers, redirect: 'manual', signal: AbortSignal.timeout(10_000),
  });
}

async function readJson(response: Response): Promise<unknown> {
  return JSON.parse(await response.text());
}

Deno.test('reference genesis comparison redacts failure messages and stacks', async () => {
  const sentinel = 'leakme';
  for (const fn of [
    async () => { JSON.parse(`{"accessJwt":${sentinel}}`); },
    async () => { loopbackOrigin(`http://[${sentinel}`); },
    async () => { await referenceRequest('http://127.0.0.1:1', 'test', `Bearer ${sentinel}\0`); },
    async () => { throw new Error(sentinel); },
  ]) {
    let error: unknown;
    try { await guarded(fn); } catch (cause) { error = cause; }
    expect(error instanceof Error && error.message === 'Reference genesis-list verification failed').toBe(true);
    expect(error instanceof Error && !(error.stack ?? '').includes(sentinel)).toBe(true);
  }
});
