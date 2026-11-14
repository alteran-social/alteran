import { expect } from '@std/expect';
import { describe, it } from './helpers/bdd';
import { P256Keypair, Secp256k1Keypair } from '@atproto/crypto-spaces';
import { createOp, createUpdateOp } from '@did-plc/lib';
import * as dagCbor from '@ipld/dag-cbor';
import { sha256 } from '@noble/hashes/sha2.js';
import { CID } from 'multiformats/cid';
import { create as createDigest } from 'multiformats/hashes/digest';
import { base58btc } from 'multiformats/bases/base58';
import { planKemPlcUpdate } from '../src/lib/spaces/kem-plc-plan';

const ORIGIN = 'https://pds.example';
const INCARNATION = '1234567890abcdef1234567890abcdef';

async function fixture() {
  const signing = await Secp256k1Keypair.create();
  const recovery = await Secp256k1Keypair.create();
  const kem = await P256Keypair.create();
  const genesis = await createOp({ signingKey: signing.did(), rotationKeys: [recovery.did(), signing.did()],
    handle: 'alice.test', pds: ORIGIN, signer: signing });
  const head = await createUpdateOp(genesis.op, signing, (operation) => operation);
  const plan = (text: unknown, captures: readonly unknown[] = []) => planKemPlcUpdate(text,
    captures[0] ?? genesis.did, captures[1] ?? INCARNATION, captures[2] ?? true, captures[3] ?? ORIGIN,
    captures[4] ?? signing.did(), captures[5] ?? signing.did(), captures[6] ?? kem.did());
  return { signing, recovery, kem, genesis, head, plan };
}

function signedHeadCid(head: unknown): string {
  const bytes = dagCbor.encode(head);
  return CID.createV1(dagCbor.code, createDigest(0x12, sha256(bytes))).toString();
}

describe('KEM PLC planner input boundaries', () => {
  it('rejects ambiguous keys, unknown fields and unsupported operation shapes', async () => {
    const f = await fixture();
    const text = JSON.stringify(f.head);
    const duplicate = text.replace('"type":"plc_operation"', '"type":"plc_operation","\\u0074ype":"plc_operation"');
    const prototype = text.replace('"rotationKeys":', '"__proto__":{},"rotationKeys":');
    const cases = [duplicate, prototype, '', '{', 'null', '[]',
      JSON.stringify({ ...f.head, unexpected: true }),
      JSON.stringify({ ...f.head, services: { ...f.head.services, extra: {
        type: 'OtherService', endpoint: 'https://other.example', extension: 'unknown',
      } } }),
      JSON.stringify({ ...f.head, type: 'plc_tombstone' }),
      JSON.stringify({ ...f.head, prev: 'not-a-cid' }),
      JSON.stringify({ ...f.head, rotationKeys: [] }),
      JSON.stringify({ ...f.head, rotationKeys: [f.signing.did(), f.signing.did()] }),
      JSON.stringify({ ...f.head, verificationMethods: { ...f.head.verificationMethods, extra: 'did:key:z0' } }),
    ];
    for (const [index, value] of cases.entries()) {
      if (f.plan(value).tag !== 'blocked') throw new Error(`Malformed case ${index} was accepted`);
    }
  });

  it('rejects unpaired surrogate values and keys without rejecting replacement characters', async () => {
    const f = await fixture();
    const badValue = { ...f.head, alsoKnownAs: [...f.head.alsoKnownAs, '\ud800'] };
    const badKey = { ...f.head, services: { ...f.head.services, ['\udfff']: {
      type: 'OtherService', endpoint: 'https://other.example',
    } } };
    const replacement = { ...f.head, alsoKnownAs: [...f.head.alsoKnownAs, '\ufffd'] };
    expect(f.plan(JSON.stringify(badValue))).toEqual({ tag: 'blocked', reason: 'invalidHead' });
    expect(f.plan(JSON.stringify(badKey))).toEqual({ tag: 'blocked', reason: 'invalidHead' });
    expect(f.plan(JSON.stringify(replacement)).tag).toBe('proposed');
    expect(f.plan(`{"type":"\ud800"}`).tag).toBe('blocked');
  });

  it('does not inspect caller-owned objects or accept non-string head bytes', async () => {
    const f = await fixture();
    let touched = false;
    const hostile = new Proxy({}, { get() { touched = true; throw new Error('unexpected getter'); } });
    expect(f.plan(hostile).tag).toBe('blocked');
    expect(planKemPlcUpdate(JSON.stringify(f.head), hostile, INCARNATION, true, ORIGIN,
      f.signing.did(), f.signing.did(), f.kem.did()).tag).toBe('blocked');
    expect(planKemPlcUpdate(JSON.stringify(f.head), f.genesis.did, INCARNATION, true, hostile,
      f.signing.did(), f.signing.did(), f.kem.did()).tag).toBe('blocked');
    expect(f.plan(new Uint8Array([0xff])).tag).toBe('blocked');
    expect(touched).toBe(false);
  });

  it('rejects malformed and noncanonical signature encodings', async () => {
    const f = await fixture();
    const impossible = btoa('\xff'.repeat(64)).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
    const highSecond = btoa(`${'\0'.repeat(31)}\x01${'\xff'.repeat(32)}`)
      .replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
    for (const signature of ['', 'not-base64!', 'A'.repeat(85), 'A'.repeat(87), 'A'.repeat(86),
      `${'A'.repeat(85)}B`, impossible, highSecond, null]) {
      const result = f.plan(JSON.stringify({ ...f.head, sig: signature }));
      expect(result).toEqual({ tag: 'blocked', reason: 'invalidHead' });
    }
  });

  it('preserves syntactically valid non-rotation did:key methods', async () => {
    const f = await fixture();
    const encoded = base58btc.encode(Uint8Array.from([0xed, 0x01, ...new Uint8Array(32).fill(7)]));
    const head = { ...f.head, verificationMethods: { ...f.head.verificationMethods, secondary: `did:key:${encoded}` } };
    const result = f.plan(JSON.stringify(head));
    expect(result.tag).toBe('proposed');
    if (result.tag !== 'proposed') throw new Error('Expected an additional method');
    expect(result.operation.verificationMethods.secondary).toBe(`did:key:${encoded}`);
  });

  it('treats endpoint syntax and distinct local key captures conservatively', async () => {
    const f = await fixture();
    for (const endpoint of [
      'https://other.example', 'https://pds.example/path', 'https://pds.example/?q=1',
      'https://pds.example/#fragment', 'https://name@pds.example', 'http://pds.example',
    ]) {
      const head = { ...f.head, services: { ...f.head.services, atproto_pds: {
        type: 'AtprotoPersonalDataServer', endpoint,
      } } };
      expect(f.plan(JSON.stringify(head))).toEqual({ tag: 'blocked', reason: 'identityMismatch' });
    }
    expect(f.plan(JSON.stringify(f.head), [undefined, undefined, undefined, undefined,
      undefined, f.kem.did(), f.kem.did()])).toEqual({ tag: 'blocked', reason: 'invalidInput' });
  });

  it('accounts for the full future compact signature at the size boundary', async () => {
    const f = await fixture();
    const prefix = 'https://extra.example/';
    const padded = (fixedCount: number, fixedLength: number, variableLength: number) => {
      const services: Record<string, { type: string; endpoint: string }> = { ...f.head.services };
      for (let index = 0; index < fixedCount; index++) {
        services[`extra${index}`] = { type: 'OtherService', endpoint: prefix + 'x'.repeat(fixedLength - prefix.length) };
      }
      services.variable = { type: 'OtherService', endpoint: prefix + 'y'.repeat(variableLength) };
      return { ...f.head, services };
    };
    const signedLength = (head: ReturnType<typeof padded>) => dagCbor.encode({ ...head,
      prev: signedHeadCid(head), verificationMethods: { ...head.verificationMethods, atproto_kem: f.kem.did() },
      sig: 'A'.repeat(86) }).byteLength;
    let boundary: ReturnType<typeof padded> | undefined;
    let oversized: ReturnType<typeof padded> | undefined;
    outer: for (let count = 1; count <= 8; count++) {
      for (let length = 480; length <= 512; length++) {
        let low = 0, high = 512 - prefix.length;
        if (signedLength(padded(count, length, low)) > 4_000 ||
          signedLength(padded(count, length, high)) <= 4_000) continue;
        while (low < high) {
          const middle = Math.ceil((low + high) / 2);
          if (signedLength(padded(count, length, middle)) <= 4_000) low = middle;
          else high = middle - 1;
        }
        const candidate = padded(count, length, low);
        const next = padded(count, length, low + 1);
        if (signedLength(candidate) === 4_000 && signedLength(next) === 4_001) {
          boundary = candidate;
          oversized = next;
          break outer;
        }
      }
    }
    if (!boundary || !oversized) throw new Error('Could not construct size boundary within field limits');
    expect(signedLength(boundary)).toBe(4_000);
    expect(signedLength(oversized)).toBe(4_001);
    const result = f.plan(JSON.stringify(boundary));
    expect(result.tag).toBe('proposed');
    if (result.tag !== 'proposed') throw new Error('Expected boundary proposal');
    expect(dagCbor.encode({ ...result.operation, sig: 'A'.repeat(86) }).byteLength).toBe(4_000);
    expect(f.plan(JSON.stringify(oversized))).toEqual({ tag: 'blocked', reason: 'tooLarge' });
  });

  it('checks the entire signed input at the size boundary', async () => {
    const f = await fixture();
    const padded = (length: number) => ({ ...f.head,
      verificationMethods: { ...f.head.verificationMethods, atproto_kem: f.kem.did() },
      alsoKnownAs: [`https://profile.example/${'x'.repeat(length)}`] });
    let low = 0, high = 7_500;
    while (low < high) {
      const middle = Math.ceil((low + high) / 2);
      if (dagCbor.encode(padded(middle)).byteLength <= 7_500) low = middle;
      else high = middle - 1;
    }
    expect(dagCbor.encode(padded(low)).byteLength).toBe(7_500);
    expect(dagCbor.encode(padded(low + 1)).byteLength).toBe(7_501);
    expect(f.plan(JSON.stringify(padded(low))).tag).toBe('matches');
    expect(f.plan(JSON.stringify(padded(low + 1))).tag).toBe('blocked');
  });

  it('bounds input and returns fixed errors without echoing private values', async () => {
    const f = await fixture();
    const sentinel = 'private-sentinel-for-planner-test';
    for (const text of [sentinel, `{ "${sentinel}":`, 'x'.repeat(65_537)]) {
      const result = f.plan(text);
      expect(result.tag).toBe('blocked');
      expect(JSON.stringify(result).includes(sentinel)).toBe(false);
    }
    const nested = `${'['.repeat(65)}0${']'.repeat(65)}`;
    expect(f.plan(nested).tag).toBe('blocked');
  });
});
