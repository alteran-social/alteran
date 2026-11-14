import { encode, decode } from '@atproto/lex-cbor';
import { lexParse, lexStringify } from '@atproto/lex-json';
import { sha256 } from '@noble/hashes/sha2.js';
import { CID } from 'multiformats/cid';
import { create as createDigest } from 'multiformats/hashes/digest';
import { serializeSpaceRecordValue } from '../src/lib/spaces/record-response';

let seed = 0x573a21;
function random(max: number) { seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0; return seed % max; }
const cid = CID.parse('bafkreigh2akiscaildcw453tj2mzyv4eicv7yqmx26iubepzwcndhy6eyu');
function generate(depth: number): unknown {
  const choice = random(depth > 0 ? 14 : 10);
  switch (choice) {
    case 0: return null;
    case 1: return random(2) === 0;
    case 2: return ['x', '\0', '🚀', '9007199254740993'][random(4)];
    case 3: return [0, -1, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER][random(4)];
    case 4: return new Uint8Array([random(256), random(256)]);
    case 5: return cid;
    case 6: return { $link: random(2) ? 'bad' : cid.toString() };
    case 7: return { $bytes: random(2) ? '***' : 'AP8' };
    case 8: return { $type: random(2) ? 'blob' : '', ref: cid, mimeType: 'text/plain', size: 1 };
    case 9: return Object.defineProperty({}, '__proto__', { value: 'x', enumerable: true });
    case 10: return [generate(depth - 1), generate(depth - 1)];
    case 11: return { a: generate(depth - 1), b: generate(depth - 1) };
    case 12: return { $type: 'com.example.nested', value: generate(depth - 1) };
    default: return { rawJSON: '1', value: generate(depth - 1) };
  }
}
function equal(a: Uint8Array, b: Uint8Array) { return a.length === b.length && a.every((x, i) => x === b[i]); }
const identity = { space: 'at://did:example:test/space/com.example.notes/room', repo: 'did:example:test',
  collection: 'com.example.note', rkey: 'one' };
Deno.test('lossless serializer preserves strict Lex compatibility for generated records', () => {
  let accepted = 0, rejected = 0;
  for (let index = 0; index < 10_000; index++) {
    const field = generate(4);
    let safe: Uint8Array, large: Uint8Array;
    try {
      safe = encode({ $type: identity.collection, n: 0, field } as never);
      large = encode({ $type: identity.collection, n: 9007199254740993n, field } as never);
    } catch { continue; }
    let expected = false;
    try { expected = equal(encode(lexParse(lexStringify(decode(safe)), { strict: true })), safe); } catch { /* Strict parsing rejects it. */ }
    const input = { value: large, cid: CID.createV1(0x71, createDigest(0x12, sha256(large))).toString() };
    let actual = false;
    try { serializeSpaceRecordValue(identity, input); actual = true; } catch { /* Strict parsing rejects it. */ }
    if (expected !== actual) throw new Error(`Mismatch on generated case ${index}`);
    if (actual) accepted++; else rejected++;
  }
  if (accepted === 0 || rejected === 0) throw new Error('Insufficient generated compatibility coverage');
});
