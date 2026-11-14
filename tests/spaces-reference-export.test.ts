import { isValidDid } from '@atproto/syntax-spaces';
import { expect } from '@std/expect';
import { makeEnv } from './helpers/env';
import { applySpaceWrites, createLocalSpace } from '../src/db/space-store';
import { streamSpaceRepoArchive } from '../src/services/space-repo-export';

const configPath = Deno.env.get('ALTERAN_REFERENCE_INTEROP_CONFIG');
const COLLECTION = 'com.example.note';

Deno.test({
  name: 'reference PDS imports an Alteran streamed STAR archive',
  ignore: !configPath,
  sanitizeOps: false,
  sanitizeResources: false,
  async fn() {
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
      const headers = new Headers(init.headers);
      headers.set('Authorization', authorization);
      const response = await fetch(`${pds}/xrpc/${method}`, {
        ...init, headers, redirect: 'manual', signal: AbortSignal.timeout(10_000),
      });
      if (!response.ok) {
        const failure = await response.json().catch(() => ({})) as { error?: unknown };
        const code = typeof failure.error === 'string' ? failure.error : 'UnknownError';
        throw new Error(`Reference PDS returned HTTP ${response.status}: ${code}`);
      }
      return response;
    }
    const post = (method: string, body: unknown) => rpc(method, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
    });
    let created = false;
    try {
      await post('com.atproto.space.createSpace', {
        spaceType: COLLECTION, skey, policy: { $type: 'com.atproto.personalspace.policy' },
      });
      created = true;
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
      expect(record.value).toEqual({ $type: COLLECTION, text: 'streamed from Alteran' });
      const commit = await (await rpc(`com.atproto.space.getLatestCommit?${new URLSearchParams({ space, repo })}`))
        .json() as { commit: { data: { $bytes: string } } };
      const referenceDigest = Uint8Array.from(atob(commit.commit.data.$bytes), (char) => char.charCodeAt(0));
      expect([...referenceDigest]).toEqual([...exportResult.commit.data]);
    } finally {
      if (created) await post('com.atproto.space.deleteSpace', { space });
    }
  },
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
