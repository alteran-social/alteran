import { expect } from '@std/expect';
import { P256Keypair, formatDidVerificationMethod } from '@atproto/crypto-spaces';
import { encode } from '@atproto/lex-cbor';
import { lexParse } from '@atproto/lex-json';
import { decapsulate, encapsulate, formatMacRequest, isP256DidKey, RECORD_MAC_PROFILE, verifyRecord } from '@atproto/space';
import { isSpaceAtUriString, isValidDid, SpaceRef } from '@atproto/syntax-spaces';
import { createSpaceRecordResponse, verifySpaceRecordResponseMac } from '../src/lib/spaces/record-response';
import { checkSpaceKemIdentity } from '../src/lib/spaces/kem-identity';

// The optional config names a disposable loopback account and its session.
const configPath = Deno.env.get('ALTERAN_REFERENCE_INTEROP_CONFIG');
const collection = 'com.example.note';
const link = 'bafkreigh2akiscaildcw453tj2mzyv4eicv7yqmx26iubepzwcndhy6eyu';

Deno.test({
  name: 'reference PDS: record JSON and MAC response interoperability',
  ignore: !configPath,
  fn: withReferenceErrors(async () => {
    const config = JSON.parse(await Deno.readTextFile(configPath!));
    const pds = loopbackOrigin(config.pds), plc = loopbackOrigin(config.plc);
    if (!isValidDid(config.did)) {
      throw new Error('Invalid disposable reference account');
    }
    const repo = config.did as `did:${string}:${string}`;
    let access = typeof config.accessJwt === 'string' ? config.accessJwt : '';
    if (access) {
      const session = await localFetch(`${pds}/xrpc/com.atproto.server.getSession`, { headers: { authorization: `Bearer ${access}` } });
      await session.body?.cancel();
      if (!session.ok) access = '';
    }
    if (!access) {
      if (typeof config.refreshJwt !== 'string' || !config.refreshJwt) throw new Error('Reference session is unavailable');
      const refresh = await localFetch(`${pds}/xrpc/com.atproto.server.refreshSession`, {
        method: 'POST', headers: { authorization: `Bearer ${config.refreshJwt}` },
      });
      if (!refresh.ok) { await refresh.body?.cancel(); throw new Error(`Reference session refresh failed: HTTP ${refresh.status}`); }
      const session = await refresh.json() as { accessJwt?: unknown };
      if (typeof session.accessJwt !== 'string' || !session.accessJwt) throw new Error('Invalid refreshed reference session');
      access = session.accessJwt;
    }
    const authorization = `Bearer ${access}`;
    const skey = `response-${crypto.randomUUID()}`;
    const space = `at://${repo}/space/${collection}/${skey}`;
    const identity = { space, repo, collection, rkey: 'one' };
    const rpc = async (name: string, init: RequestInit = {}) => {
      const headers = new Headers(init.headers); headers.set('authorization', authorization);
      const response = await localFetch(`${pds}/xrpc/${name}`, { ...init, headers });
      if (!response.ok) { await response.body?.cancel(); throw new Error(`${name.split('?')[0]} failed: HTTP ${response.status}`); }
      return response;
    };
    const post = (name: string, body: unknown) => rpc(name, { method: 'POST',
      headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    const documentResponse = await localFetch(`${plc}/${encodeURIComponent(repo)}`);
    if (!documentResponse.ok) { await documentResponse.body?.cancel(); throw new Error('Reference DID lookup failed'); }
    const document = await documentResponse.json() as { verificationMethod?: {
      id?: string; controller?: string; type?: string; publicKeyMultibase?: string;
    }[] };
    const methods = document.verificationMethod?.filter((method: {id?: string}) => method.id === '#atproto_kem' || method.id === `${repo}#atproto_kem`);
    const method = methods?.[0];
    if (!method || methods?.length !== 1 || method.controller !== repo || !method.type || !method.publicKeyMultibase) throw new Error('Invalid reference KEM method');
    const kem = formatDidVerificationMethod({ type: method.type, publicKeyMultibase: method.publicKeyMultibase });
    if (!isP256DidKey(kem) || checkSpaceKemIdentity(repo, kem, document) !== 'ready') throw new Error('Invalid reference KEM key');
    let attempted = false;
    try {
      attempted = true;
      await (await post('com.atproto.space.createSpace', { spaceType: collection, skey, policy: { $type: 'com.atproto.personalspace.policy' } })).body?.cancel();
      await (await post('com.atproto.space.createRecord', { space, repo, collection, rkey: 'one', validate: false,
        record: { $type: collection, text: 'reference response', nested: { link: { $link: link }, bytes: { $bytes: 'AP8' } } } })).body?.cancel();
      const query = new URLSearchParams(identity);
      const own = await rpc(`com.atproto.space.getRecord?${query}`);
      expect(own.headers.get('signature') === null).toBe(true);
      expect(own.headers.get('vary')?.toLowerCase().includes('accept-signature') === true).toBe(true);
      const ownBody = await own.json();
      const referenceShared = await encapsulate(kem);
      const signed = await rpc(`com.atproto.space.getRecord?${query}`, {
        headers: { 'accept-signature': formatMacRequest(RECORD_MAC_PROFILE, referenceShared.keyShare) },
      });
      const referenceText = await signed.text();
      const referenceJson = JSON.parse(referenceText) as {uri: string; cid: string; value: unknown};
      expect(sameJson(referenceJson, ownBody)).toBe(true);
      const uri = SpaceRef.parse(space).recordUri(repo, collection, 'one').toString();
      if (!isSpaceAtUriString(uri)) throw new Error('Invalid record URI');
      expect(referenceJson.uri === uri).toBe(true);
      const lex = lexParse(referenceText, { strict: true }) as {uri: string; cid: string; value: never};
      await verifyRecord(lex as never, { ...referenceShared, headers: signed.headers, uri });
      const bytes = encode(lex.value);
      const hostKey = await P256Keypair.create(), client = await encapsulate(hostKey.did() as `did:${string}:${string}`);
      const kemKey = { publicDidKey: hostKey.did(), deriveSharedSecret: (keyShare: string) => decapsulate(hostKey, keyShare as `did:${string}:${string}`) };
      const actual = createSpaceRecordResponse(identity, { cid: referenceJson.cid, value: bytes }, {
        acceptSignature: formatMacRequest(RECORD_MAC_PROFILE, client.keyShare), kemKey, requireMac: true,
      });
      expect(sameJson(JSON.parse(actual.body), referenceJson)).toBe(true);
      expect(actual.headers['atproto-space-record'] === signed.headers.get('atproto-space-record')).toBe(true);
      expect(verifySpaceRecordResponseMac(identity, referenceJson.cid, new Headers(actual.headers), client)).toBe(true);
      await verifyRecord(lexParse(actual.body, { strict: true }) as never, { ...client, headers: new Headers(actual.headers), uri });
    } finally {
      if (attempted) await (await post('com.atproto.space.deleteSpace', { space })).body?.cancel();
    }
  }),
});

function loopbackOrigin(input: unknown): string {
  if (typeof input !== 'string') throw new Error('Expected loopback URL');
  const url = new URL(input);
  if (url.protocol !== 'http:' || !['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname) ||
    url.username || url.password || url.pathname !== '/' || url.search || url.hash) throw new Error('Only loopback origins are allowed');
  return url.origin;
}
function localFetch(input: string, init: RequestInit = {}): Promise<Response> {
  const url = new URL(input); loopbackOrigin(url.origin);
  if (url.username || url.password) throw new Error('Credentials in URLs are not allowed');
  return fetch(url, { ...init, redirect: 'manual', signal: AbortSignal.timeout(10_000) });
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
