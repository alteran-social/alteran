import { expect } from '@std/expect';
import { describe, it } from './helpers/bdd';
import { P256Keypair } from '@atproto/crypto-spaces';
import type { Env } from '../src/env';
import { parseUniqueIdentityJson } from '../src/lib/spaces/identity-json';
import { resolveLocalSpaceKemIdentity } from '../src/lib/spaces/local-kem-identity';

const DID = `did:plc:${'a'.repeat(24)}`;
const KEY = `${'0'.repeat(63)}1`;
const OTHER_KEY = `${'0'.repeat(63)}2`;
const ORIGIN = 'https://pds.example.com';

function env(overrides: Record<string, unknown> = {}): Env {
  return { PDS_DID: DID, PDS_HANDLE: 'alice.example.com', PDS_HOSTNAME: ORIGIN,
    PDS_SPACE_KEM_KEY: KEY, ...overrides } as Env;
}

async function document() {
  const key = await P256Keypair.import(KEY, { exportable: false });
  return { id: DID, verificationMethod: [{ id: `${DID}#atproto_kem`, controller: DID,
    type: 'Multikey', publicKeyMultibase: key.did().slice('did:key:'.length) }],
  service: [{ id: '#atproto_pds', type: 'AtprotoPersonalDataServer', serviceEndpoint: ORIGIN }] };
}

function response(text: string | Uint8Array, contentType = 'application/did+json'): Response {
  const bytes = typeof text === 'string' ? new TextEncoder().encode(text) : text;
  const stream = new ReadableStream({ type: 'bytes', start(controller: ReadableByteStreamController) {
    controller.enqueue(bytes); controller.close();
  } });
  return new Response(stream, { headers: { 'Content-Type': contentType } });
}

async function withFetch<T>(fetcher: typeof fetch, action: () => Promise<T>): Promise<T> {
  const original = globalThis.fetch;
  globalThis.fetch = fetcher;
  try { return await action(); } finally { globalThis.fetch = original; }
}

describe('local Space KEM identity', () => {
  it('rejects duplicate decoded names, malformed JSON and excessive nesting', () => {
    expect(parseUniqueIdentityJson('{"id":1,"\\u0069d":2}')).toBeNull();
    expect(parseUniqueIdentityJson('{"outer":{"x":1,"x":2}}')).toBeNull();
    expect(parseUniqueIdentityJson('{"__proto__":1}')).toBeNull();
    expect(parseUniqueIdentityJson('{"x":1,}')).toBeNull();
    expect(parseUniqueIdentityJson(`${'{"a":'.repeat(65)}0${'}'.repeat(65)}`)).toBeNull();
    expect(parseUniqueIdentityJson('{"one":{"x":"}:\\\""},"two":{"x":2}}')).toEqual({
      one: { x: '}:' + '"' }, two: { x: 2 },
    });
  });

  it('returns the configured key only after a bounded fresh DID document matches', async () => {
    const doc = await document();
    let requested = '';
    const result = await withFetch((async (url: RequestInfo | URL, init?: RequestInit) => {
      requested = String(url);
      expect(init?.redirect).toBe('manual');
      expect(init?.cache).toBe('no-store');
      return response(JSON.stringify(doc));
    }) as typeof fetch, () => resolveLocalSpaceKemIdentity(env(), DID, new AbortController().signal));
    expect(requested).toBe(`https://plc.directory/${DID}`);
    expect(result.tag).toBe('ready');
    if (result.tag === 'ready') expect(result.did).toBe(DID);
  });

  it('rejects mismatched account, key, service, duplicate names and non-JSON responses', async () => {
    const doc = await document();
    let calls = 0;
    const matching = (async () => { calls++; return response(JSON.stringify(doc)); }) as typeof fetch;
    expect((await withFetch(matching, () => resolveLocalSpaceKemIdentity(env(), 'did:plc:wrong', new AbortController().signal))).tag).toBe('invalid');
    expect(calls).toBe(0);
    expect((await withFetch(matching, () => resolveLocalSpaceKemIdentity(env({ PDS_SPACE_KEM_KEY: '' }), DID, new AbortController().signal))).tag).toBe('missing');
    for (const input of [
      JSON.stringify({ ...doc, service: [{ ...doc.service[0], serviceEndpoint: 'https://other.example.com' }] }),
      JSON.stringify({ ...doc, service: [doc.service[0], doc.service[0]] }),
      JSON.stringify({ ...doc, verificationMethod: [{ ...doc.verificationMethod[0], controller: 'did:plc:other' }] }),
      `{"id":"${DID}","\\u0069d":"${DID}","verificationMethod":[],"service":[]}`,
    ]) {
      const result = await withFetch((async () => response(input)) as typeof fetch,
        () => resolveLocalSpaceKemIdentity(env(), DID, new AbortController().signal));
      expect(['invalid', 'mismatch']).toContain(result.tag);
    }
    const wrongType = await withFetch((async () => response(JSON.stringify(doc), 'text/html')) as typeof fetch,
      () => resolveLocalSpaceKemIdentity(env(), DID, new AbortController().signal));
    expect(wrongType.tag).toBe('unavailable');
  });

  it('requires an explicit HTTPS host without credentials, paths or fallback', async () => {
    const doc = await document();
    const matching = (async () => response(JSON.stringify(doc))) as typeof fetch;
    for (const host of [
      '', undefined, 'http://pds.example.com', 'https://name:password@pds.example.com/private?x=1#fragment',
      'https://pds.example.com/private', 'https://pds.example.com?', 'https://pds.example.com#',
      'pds.example.com/path', 'pds.example.com@other.example.com',
    ]) {
      const result = await withFetch(matching,
        () => resolveLocalSpaceKemIdentity(env({ PDS_HOSTNAME: host }), DID, new AbortController().signal));
      expect(result.tag).toBe('invalid');
    }
    const bare = await withFetch(matching,
      () => resolveLocalSpaceKemIdentity(env({ PDS_HOSTNAME: 'pds.example.com' }), DID, new AbortController().signal));
    expect(bare.tag).toBe('ready');
    for (const endpoint of ['https://pds.example.com/.', 'https://pds.example.com?', 'https://pds.example.com#']) {
      const badDoc = { ...doc, service: [{ ...doc.service[0], serviceEndpoint: endpoint }] };
      const result = await withFetch((async () => response(JSON.stringify(badDoc))) as typeof fetch,
        () => resolveLocalSpaceKemIdentity(env(), DID, new AbortController().signal));
      expect(result.tag).toBe('mismatch');
    }
  });

  it('withholds the capability if the configured key changes during resolution', async () => {
    const doc = await document();
    let current = KEY;
    const binding = { get: async () => current };
    const result = await withFetch((async () => { current = OTHER_KEY; return response(JSON.stringify(doc)); }) as typeof fetch,
      () => resolveLocalSpaceKemIdentity(env({ PDS_SPACE_KEM_KEY: binding }), DID, new AbortController().signal));
    expect(result.tag).toBe('unavailable');
  });

  it('bounds hanging secret reads and starts no late fetch after timeout', async () => {
    let release: (value: string) => void = () => {};
    let calls = 0;
    const binding = { get: () => new Promise<string>((resolve) => { release = resolve; }) };
    const result = await withFetch((async () => { calls++; return response('{}'); }) as typeof fetch, async () => {
      const pending = resolveLocalSpaceKemIdentity(env({ PDS_DID: binding }), DID, new AbortController().signal, 20);
      const settled = await pending;
      release(DID);
      await new Promise((resolve) => setTimeout(resolve, 10));
      return settled;
    });
    expect(result.tag).toBe('timeout');
    expect(calls).toBe(0);
  });

  it('rejects invalid UTF-8 and documents larger than the byte budget', async () => {
    const invalid = await withFetch((async () => response(Uint8Array.of(0xff))) as typeof fetch,
      () => resolveLocalSpaceKemIdentity(env(), DID, new AbortController().signal));
    expect(invalid.tag).toBe('invalid');
    const tooLarge = await withFetch((async () => response(' '.repeat(65_537))) as typeof fetch,
      () => resolveLocalSpaceKemIdentity(env(), DID, new AbortController().signal));
    expect(tooLarge.tag).toBe('unavailable');
  });

  it('times out and cancels a stalled document body', async () => {
    let cancelled = false;
    const stalled = new ReadableStream({ type: 'bytes', start(controller: ReadableByteStreamController) {
      controller.enqueue(new TextEncoder().encode('{"id":'));
    }, cancel() { cancelled = true; } });
    const result = await withFetch((async () => new Response(stalled, {
      headers: { 'Content-Type': 'application/did+json' },
    })) as typeof fetch, () => resolveLocalSpaceKemIdentity(env(), DID, new AbortController().signal, 20));
    await new Promise((resolve) => setTimeout(resolve, 5));
    expect(result.tag).toBe('timeout');
    expect(cancelled).toBe(true);
  });

  it('honors cancellation before and during a stalled fetch', async () => {
    const aborted = new AbortController(); aborted.abort();
    expect((await resolveLocalSpaceKemIdentity(env(), DID, aborted.signal)).tag).toBe('aborted');
    const controller = new AbortController();
    const result = await withFetch((async () => {
      controller.abort();
      return await new Promise<Response>(() => {});
    }) as typeof fetch, () => resolveLocalSpaceKemIdentity(env(), DID, controller.signal, 1000));
    expect(result.tag).toBe('aborted');
  });
});
