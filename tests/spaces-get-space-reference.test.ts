import { isValidDid } from '@atproto/syntax-spaces';
import { expect } from '@std/expect';
import { EMPTY, policyContext, policyFixture, signedPolicyRequest } from './helpers/spaces-policy-read';
import { beginPersonalSpaceDeletion } from '../src/db/space-lifecycle-delete';
import { GET } from '../src/pages/xrpc/com.atproto.space.getSpace';

const configPath = Deno.env.get('ALTERAN_REFERENCE_INTEROP_CONFIG');

Deno.test({
  name: 'reference PDS agrees on fresh and deleted personal Space policy',
  ignore: !configPath,
  sanitizeOps: false,
  sanitizeResources: false,
  async fn() {
    if (!configPath) throw new Error('Missing reference configuration');
    const data: unknown = await readConfig(configPath);
    if (!data || typeof data !== 'object') throw new Error('Invalid reference configuration');
    const config = data as Record<string, unknown>;
    const origin = loopbackOrigin(config.pds);
    if (!isValidDid(config.did) || typeof config.accessJwt !== 'string' || !config.accessJwt) {
      throw new Error('Invalid disposable reference account');
    }
    const spaceType = 'com.example.notes';
    const skey = `getspace-${crypto.randomUUID()}`;
    const space = `at://${config.did}/space/${spaceType}/${skey}`;
    const authorization = `Bearer ${config.accessJwt}`;
    const send = (name: string, init: RequestInit = {}) => referenceRequest(origin, name, authorization, init);
    const post = (name: string, body: unknown) => send(name, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
    });
    let attempted = false;
    let deleted = false;
    try {
      attempted = true;
      const create = await post('com.atproto.space.createSpace', {
        spaceType, skey, policy: { $type: 'com.atproto.personalspace.policy' },
      });
      if (!create.ok) throw new Error(`Reference create failed: HTTP ${create.status}`);
      expect((await readJson(create) as { space?: unknown }).space === space).toBe(true);
      const reference = await send(`com.atproto.space.getSpace?${new URLSearchParams({ space })}`);
      expect(reference.status).toBe(200);
      const refBody = await readJson(reference) as { space?: unknown; policy?: unknown };
      const f = await policyFixture();
      const local = await GET(policyContext(f.env, await signedPolicyRequest(f)));
      expect(local.status).toBe(200);
      const localBody = await readJson(local) as { space?: unknown; policy?: unknown };
      expect(refBody.space === space).toBe(true);
      expect(localBody.space === EMPTY).toBe(true);
      expect(isPersonalPolicy(localBody.policy) && isPersonalPolicy(refBody.policy)).toBe(true);
      expect(hasExpectedFields(localBody) && hasExpectedFields(refBody)).toBe(true);
      const deletion = await post('com.atproto.space.deleteSpace', { space });
      if (!deletion.ok) throw new Error(`Reference deletion failed: HTTP ${deletion.status}`);
      deleted = true;
      try { await deletion.body?.cancel(); } catch { throw new Error('Reference response failed'); }
      const missing = await send(`com.atproto.space.getSpace?${new URLSearchParams({ space })}`);
      expect(missing.status).toBe(400);
      expect((await readJson(missing) as { error?: unknown }).error === 'SpaceNotFound').toBe(true);
      expect((await beginPersonalSpaceDeletion(f.env, EMPTY, crypto.randomUUID(), f.owner.incarnation)).tag).toBe('started');
      const localMissing = await GET(policyContext(f.env, await signedPolicyRequest(f)));
      expect(localMissing.status).toBe(400);
      expect((await readJson(localMissing) as { error?: unknown }).error === 'SpaceNotFound').toBe(true);
    } finally {
      if (attempted && !deleted) {
        try {
          const cleanup = await post('com.atproto.space.deleteSpace', { space });
          if (!cleanup.ok) {
            if ((await readJson(cleanup) as { error?: unknown }).error !== 'SpaceNotFound') {
              throw new Error('Reference cleanup failed');
            }
          } else await cleanup.body?.cancel();
        } catch { throw new Error('Reference cleanup failed'); }
      }
    }
  },
});

function loopbackOrigin(value: unknown): string {
  if (typeof value !== 'string') throw new Error('A loopback URL is required');
  try {
    const url = new URL(value);
    if (url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname) &&
      !url.username && !url.password && url.pathname === '/' && !url.search && !url.hash) return url.origin;
  } catch { /* Reject malformed or non-loopback origins below. */ }
  throw new Error('Only a loopback reference PDS origin is allowed');
}

function parseJson(text: string): unknown {
  try { return JSON.parse(text); } catch { throw new Error('Invalid reference JSON'); }
}

async function referenceRequest(origin: string, name: string, authorization: string, init: RequestInit = {}) {
  try {
    const headers = new Headers(init.headers);
    headers.set('authorization', authorization);
    return await fetch(`${origin}/xrpc/${name}`, {
      ...init, headers, redirect: 'manual', signal: AbortSignal.timeout(10_000),
    });
  } catch { throw new Error('Reference request failed'); }
}

async function readConfig(path: string): Promise<unknown> {
  try { return parseJson(await Deno.readTextFile(path)); } catch { throw new Error('Invalid reference configuration'); }
}

async function readJson(response: Response): Promise<unknown> {
  try { return parseJson(await response.text()); } catch { throw new Error('Invalid reference response'); }
}

function isPersonalPolicy(value: unknown): boolean {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const policy = value as Record<string, unknown>;
  return Object.keys(policy).length === 1 && policy.$type === 'com.atproto.personalspace.policy';
}

function hasExpectedFields(value: { space?: unknown; policy?: unknown }): boolean {
  return !!value && typeof value === 'object' && Object.keys(value).length === 2 &&
    Object.hasOwn(value, 'space') && Object.hasOwn(value, 'policy');
}

Deno.test('reference failures do not expose credentials', async () => {
  const sentinel = 'credential-sentinel-for-test';
  const cases = [
    [() => parseJson(`{"accessJwt":${sentinel}}`), 'Invalid reference JSON'],
    [() => referenceRequest('http://127.0.0.1:1', 'test', `Bearer ${sentinel}\0`), 'Reference request failed'],
  ] as const;
  for (const [run, message] of cases) {
    let error: unknown;
    try { await run(); } catch (cause) { error = cause; }
    expect(error instanceof Error && error.message === message).toBe(true);
    expect(error instanceof Error && !(error.stack ?? '').includes(sentinel)).toBe(true);
  }
});
