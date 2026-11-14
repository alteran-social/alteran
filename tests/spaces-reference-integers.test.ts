import * as dagCbor from '@ipld/dag-cbor';
import { decode } from '@atproto/lex-cbor';
import { writeRepoStar } from '@atproto/space';
import { isValidDid, SpaceRef } from '@atproto/syntax-spaces';
import { sha256 } from '@noble/hashes/sha2.js';
import { CID } from 'multiformats/cid';
import { create as createDigest } from 'multiformats/hashes/digest';
import { readSpaceRepoArchive } from '../src/lib/spaces/repo-archive';
import { applySpaceSetHashChanges, spaceRecordHashElement, spaceSetHashDigest } from '../src/lib/spaces/lthash';
import { createSpaceRecordResponse } from '../src/lib/spaces/record-response';
import { createSpaceListResponse } from '../src/lib/spaces/list-record-response';
import { validSpaceRecordBlock } from '../src/db/space-record-block';

const configPath = Deno.env.get('ALTERAN_REFERENCE_INTEROP_CONFIG');
const COLLECTION = 'com.example.note';
const SAMPLES = [
  ['safe', '9007199254740991'], ['positive_exact', '9007199254740992'],
  ['positive_inexact', '9007199254740993'], ['negative_inexact', '-9007199254740993'],
  ['max', '9223372036854775807'], ['min', '-9223372036854775808'],
] as const;

Deno.test({
  name: 'reference PDS preserves signed 64-bit Space integers without silent JSON rounding',
  ignore: !configPath,
  sanitizeOps: false,
  sanitizeResources: false,
  async fn() {
    if (!configPath) throw new Error('Missing reference configuration');
    const config = await readConfig(configPath);
    if (!config || typeof config !== 'object') throw new Error('Invalid reference configuration');
    const fields = config as Record<string, unknown>;
    const origin = loopbackOrigin(fields.pds);
    if (!validReferenceDid(fields.did) || typeof fields.accessJwt !== 'string' || !fields.accessJwt) {
      throw new Error('Invalid disposable reference account');
    }
    const repo = fields.did;
    const skey = `integers-${crypto.randomUUID()}`;
    const space = `at://${repo}/space/${COLLECTION}/${skey}`;
    const authorization = `Bearer ${fields.accessJwt}`;
    const rpc = (name: string, init: RequestInit = {}) => referenceRequest(origin, name, authorization, init);
    const post = (name: string, body: unknown) => rpc(name, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
    });
    const requireOk = async (response: Response, stage: string) => {
      if (!response.ok) {
        await cancelResponse(response);
        throw new Error(`Reference ${stage} returned HTTP ${response.status}`);
      }
      return response;
    };
    let attempted = false;
    try {
      attempted = true;
      await cancelResponse(await requireOk(await post('com.atproto.space.createSpace', {
        spaceType: COLLECTION, skey, policy: { $type: 'com.atproto.personalspace.policy' },
      }), 'createSpace'));
      await cancelResponse(await requireOk(await post('com.atproto.space.createRecord', {
        space, repo, collection: COLLECTION, rkey: 'initial', validate: false,
        record: { $type: COLLECTION, text: 'fixture' },
      }), 'createRecord'));
      const query = new URLSearchParams({ space, repo });
      const initial = await requireOk(await rpc(`com.atproto.space.getRepo?${query}`), 'getRepo');
      const base = await readArchive(initial, space, repo);
      const records = SAMPLES.map(([rkey, integer]) => {
        const bytes = dagCbor.encode({ $type: COLLECTION, n: BigInt(integer) });
        const cid = CID.createV1(0x71, createDigest(0x12, sha256(bytes))).toString();
        return { collection: COLLECTION, rkey, cid, bytes, integer } as const;
      }).sort((a, b) => a.rkey < b.rkey ? -1 : a.rkey > b.rkey ? 1 : 0);
      const state = applySpaceSetHashChanges(null, records.map((record) => ({
        action: 'add', element: spaceRecordHashElement(record.collection, record.rkey, record.cid),
      })));
      const commit = { ver: 1 as const, space: SpaceRef.parse(space).toString(), repo, rev: base.rev,
        data: spaceSetHashDigest(state) };
      const chunks: Uint8Array[] = [];
      let length = 0;
      for await (const chunk of writeRepoStar(commit, records)) {
        chunks.push(chunk);
        length += chunk.byteLength;
      }
      const archive = new Uint8Array(length);
      let offset = 0;
      for (const chunk of chunks) {
        archive.set(chunk, offset);
        offset += chunk.byteLength;
      }
      await cancelResponse(await requireOk(await rpc('com.atproto.space.importRepo', {
        method: 'POST', headers: { 'content-type': 'application/vnd.dasl.star' }, body: archive,
      }), 'importRepo'));
      const exported = await requireOk(await rpc(`com.atproto.space.getRepo?${query}`), 'exported getRepo');
      const saved = await readArchive(exported, space, repo);
      ensure(saved.records.length === records.length, 'Unexpected exported record count');
      for (const expected of records) {
        const actual = saved.records.find((record) => record.rkey === expected.rkey);
        if (!actual) throw new Error('Missing exported integer record');
        ensure(actual.cid === expected.cid, 'Exported record CID mismatch');
        ensure(readInteger(actual.value) === expected.integer, 'Exported integer mismatch');
        ensure(validSpaceRecordBlock(COLLECTION, expected.cid, expected.bytes), 'Invalid generated record');

        const recordQuery = new URLSearchParams({ space, repo, collection: COLLECTION, rkey: expected.rkey });
        const response = await rpc(`com.atproto.space.getRecord?${recordQuery}`);
        const body = await responseText(response);
        if (expected.rkey === 'safe') ensure(response.status === 200, 'Reference safe integer read failed');
        if (response.ok) {
          const parsed = objectValue(parseJson(body));
          ensure(parsed.cid === expected.cid, 'Reference record CID mismatch');
          ensure(sameStrings(integerLiterals(body).map(String), [expected.integer]), 'Reference integer mismatch');
        } else {
          assertSanitizedFailure(response.status, body, [space, repo, fields.accessJwt, expected.integer]);
        }
        let localBody: string | undefined;
        try {
          localBody = createSpaceRecordResponse({ space, repo, collection: COLLECTION, rkey: expected.rkey },
            { cid: expected.cid, value: expected.bytes }, { acceptSignature: null, kemKey: null, requireMac: false }).body;
        } catch {
          if (expected.rkey === 'safe') throw new Error('Failed to serialize safe integer');
        }
        if (localBody !== undefined) {
          parseJson(localBody);
          ensure(sameStrings(integerLiterals(localBody).map(String), [expected.integer]), 'Local integer mismatch');
        }
      }

      const metadata = await requireOk(await rpc(`com.atproto.space.listRecords?${new URLSearchParams({
        space, repo, excludeValues: 'true',
      })}`), 'metadata listRecords');
      const metadataBody = objectValue(parseJson(await responseText(metadata)));
      const metadataRecords = metadataBody.records;
      ensure(Array.isArray(metadataRecords) && metadataRecords.length === records.length &&
        metadataRecords.every((record) => record !== null && typeof record === 'object' &&
          !Array.isArray(record) && !Object.hasOwn(record, 'value')), 'Invalid reference metadata');
      const list = await rpc(`com.atproto.space.listRecords?${new URLSearchParams({ space, repo, excludeValues: 'false' })}`);
      const listBody = await responseText(list);
      if (list.ok) {
        const parsed = objectValue(parseJson(listBody));
        ensure(Array.isArray(parsed.records), 'Invalid reference list');
        const expected = [...records].reverse();
        const keys = parsed.records.map((record: unknown) => objectValue(record).rkey);
        ensure(sameValues(keys, expected.map((record) => record.rkey)), 'Reference record order mismatch');
        ensure(sameStrings(integerLiterals(listBody).map(String), expected.map((record) => record.integer)),
          'Reference list integer mismatch');
      } else {
        assertSanitizedFailure(list.status, listBody, [space, repo, fields.accessJwt, ...records.map((record) => record.integer)]);
      }
      let localList: string | undefined;
      try {
        localList = createSpaceListResponse({ space, repo, collection: null, cursorPath: null, limit: 50, excludeValues: false },
          records.map((record) => ({ collection: record.collection, rkey: record.rkey, cid: record.cid,
            record: { cid: record.cid, value: record.bytes, rev: base.rev } })));
      } catch {
        // A rejected page is acceptable; an emitted page must retain every integer exactly.
      }
      if (localList !== undefined) {
        parseJson(localList);
        ensure(sameStrings(integerLiterals(localList).map(String), records.map((record) => record.integer)),
          'Local list integer mismatch');
      }
    } catch {
      throw new Error('Reference integer verification failed');
    } finally {
      if (attempted) {
        try {
          const deleted = await post('com.atproto.space.deleteSpace', { space });
          if (!deleted.ok) {
            const failure = objectValue(parseJson(await responseText(deleted)));
            if (failure.error !== 'SpaceNotFound') throw new Error('Reference Space cleanup failed');
          } else await cancelResponse(deleted);
        } catch {
          throw new Error('Reference Space cleanup failed');
        }
      }
    }
  },
});

function loopbackOrigin(value: unknown): string {
  try {
    if (typeof value !== 'string') throw new Error();
    const url = new URL(value);
    if (url.protocol !== 'http:' || !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname) ||
      url.username || url.password || url.pathname !== '/' || url.search || url.hash) throw new Error();
    return url.origin;
  } catch {
    throw new Error('Only a loopback reference PDS origin is allowed');
  }
}

async function referenceRequest(origin: string, name: string, authorization: string, init: RequestInit = {}) {
  try {
    const headers = new Headers(init.headers);
    headers.set('authorization', authorization);
    return await fetch(`${origin}/xrpc/${name}`, {
      ...init, headers, redirect: 'manual', signal: AbortSignal.timeout(30_000),
    });
  } catch {
    throw new Error('Reference request failed');
  }
}

async function cancelResponse(response: Response): Promise<void> {
  try { await response.body?.cancel(); } catch { throw new Error('Invalid reference response'); }
}

function assertSanitizedFailure(status: number, body: string, privateValues: readonly string[]) {
  ensure(status >= 400 && status <= 599, 'Invalid reference failure status');
  const parsed = objectValue(parseJson(body));
  ensure(typeof parsed.error === 'string' && parsed.error.length > 0, 'Invalid reference failure');
  ensure(privateValues.every((value) => !body.includes(value)), 'Reference failure contains private data');
}

function validReferenceDid(value: unknown): value is `did:${string}:${string}` {
  try {
    return isValidDid(value);
  } catch {
    return false;
  }
}

async function readConfig(path: string): Promise<unknown> {
  try {
    return parseJson(await Deno.readTextFile(path));
  } catch {
    throw new Error('Invalid reference configuration');
  }
}

function parseJson(value: string): unknown {
  try {
    return JSON.parse(value);
  } catch {
    throw new Error('Invalid JSON in reference integer test');
  }
}

function objectValue(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid reference object');
  return value as Record<string, unknown>;
}

function ensure(value: boolean, message: string): asserts value {
  if (!value) throw new Error(message);
}

function sameValues(left: readonly unknown[], right: readonly unknown[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function sameStrings(left: readonly string[], right: readonly string[]): boolean {
  return sameValues(left, right);
}

async function responseBytes(response: Response): Promise<Uint8Array> {
  const limit = 16 * 1024 * 1024;
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  try {
    if (!response.body) return new Uint8Array();
    reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let length = 0;
    for (;;) {
      const next = await reader.read();
      if (next.done) break;
      if (!(next.value instanceof Uint8Array) || next.value.byteLength > limit - length) {
        await reader.cancel();
        throw new Error();
      }
      chunks.push(next.value);
      length += next.value.byteLength;
    }
    const result = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) {
      result.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return result;
  } catch {
    throw new Error('Invalid reference response');
  } finally {
    try {
      reader?.releaseLock();
    } catch {
      // The response is already unusable.
    }
  }
}

async function responseText(response: Response): Promise<string> {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(await responseBytes(response));
  } catch {
    throw new Error('Invalid reference response');
  }
}

async function readArchive(response: Response, space: string, repo: string) {
  try {
    return await readSpaceRepoArchive(await responseBytes(response), { space, repo });
  } catch {
    throw new Error('Invalid reference archive');
  }
}

function readInteger(value: Uint8Array): string {
  try {
    const integer = objectValue(decode(value)).n;
    if (typeof integer !== 'number' && typeof integer !== 'bigint') throw new Error();
    return String(integer);
  } catch {
    throw new Error('Invalid exported integer record');
  }
}

Deno.test('reference integer failures never include credentials', async () => {
  const sentinel = 'harmless-token-sentinel';
  const malformed = `{"accessJwt":${sentinel}}`;
  const path = await Deno.makeTempFile({ prefix: 'alteran-integer-redaction-' });
  try {
    await Deno.writeTextFile(path, malformed);
    const cases = [
      [() => parseJson(malformed), 'Invalid JSON in reference integer test'],
      [() => readConfig(path), 'Invalid reference configuration'],
      [() => referenceRequest('http://127.0.0.1:1', 'test', `Bearer ${sentinel}\0`), 'Reference request failed'],
      [() => cancelResponse(new Response(new ReadableStream({ cancel() { throw new Error(sentinel); } }))),
        'Invalid reference response'],
    ] as const;
    for (const [parse, expected] of cases) {
      let error: unknown;
      try {
        await parse();
      } catch (cause) {
        error = cause;
      }
      ensure(error instanceof Error && error.message === expected, 'Reference input was not rejected safely');
      ensure(!`${error.message}\n${error.stack ?? ''}`.includes(sentinel), 'Reference failure leaked its input');
    }
  } finally {
    await Deno.remove(path);
  }
});

function integerLiterals(body: string): bigint[] {
  return Array.from(body.matchAll(/"n"\s*:\s*(-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/g),
    (match) => exactInteger(match[1]));
}

function exactInteger(value: string): bigint {
  const parts = /^(-?)([0-9]+)(?:\.([0-9]+))?(?:[eE]([+-]?[0-9]+))?$/.exec(value);
  if (!parts || value.length > 128) throw new Error('Invalid integer token');
  const fraction = parts[3] ?? '';
  const exponent = Number(parts[4] ?? 0) - fraction.length;
  if (!Number.isSafeInteger(exponent) || Math.abs(exponent) > 128) throw new Error('Invalid integer exponent');
  let integer = BigInt(parts[2] + fraction);
  if (exponent >= 0) integer *= 10n ** BigInt(exponent);
  else {
    const divisor = 10n ** BigInt(-exponent);
    if (integer % divisor !== 0n) throw new Error('Non-integral JSON number');
    integer /= divisor;
  }
  return parts[1] ? -integer : integer;
}
