import { expect } from '@std/expect';
import { describe, it } from './helpers/bdd';
import { P256Keypair, Secp256k1Keypair } from '@atproto/crypto-spaces';
import { createOp, createUpdateOp, deprecatedSignCreate, didForCreateOp, normalizeOp } from '@did-plc/lib';
import * as dagCbor from '@ipld/dag-cbor';
import { sha256 } from '@noble/hashes/sha2.js';
import { CID } from 'multiformats/cid';
import { create as createDigest } from 'multiformats/hashes/digest';
import { planKemPlcUpdate } from '../src/lib/spaces/kem-plc-plan';

const ORIGIN = 'https://pds.example';
const INCARNATION = '1234567890abcdef1234567890abcdef';

async function fixture() {
  const signing = await Secp256k1Keypair.create();
  const recovery = await Secp256k1Keypair.create();
  const kem = await P256Keypair.create();
  const other = await P256Keypair.create();
  const genesis = await createOp({ signingKey: signing.did(), rotationKeys: [recovery.did(), signing.did()],
    handle: 'alice.test', pds: ORIGIN, signer: signing });
  const plan = (head: unknown = genesis.op, overrides: {
    did?: unknown; incarnation?: unknown; active?: unknown; origin?: unknown;
    signing?: unknown; rotation?: unknown; kem?: unknown;
  } = {}) => planKemPlcUpdate(typeof head === 'string' ? head : JSON.stringify(head),
    overrides.did ?? genesis.did, overrides.incarnation ?? INCARNATION, overrides.active ?? true,
    overrides.origin ?? ORIGIN, overrides.signing ?? signing.did(), overrides.rotation ?? signing.did(),
    overrides.kem ?? kem.did());
  return { signing, recovery, kem, other, genesis, plan };
}

function plain(value: unknown): unknown {
  return JSON.parse(JSON.stringify(value));
}

function canonicalCid(value: unknown): string {
  const bytes = dagCbor.encode(value);
  return CID.createV1(dagCbor.code, createDigest(0x12, sha256(bytes))).toString();
}

describe('unsigned KEM PLC planning', () => {
  it('matches the reference update and hashes the original signed genesis', async () => {
    const f = await fixture();
    const result = f.plan();
    expect(result.tag).toBe('proposed');
    if (result.tag !== 'proposed') throw new Error('Expected a proposed operation');
    const reference = await createUpdateOp(f.genesis.op, f.signing, (current) => ({
      ...current, verificationMethods: { ...current.verificationMethods, atproto_kem: f.kem.did() },
    }));
    const { sig: _signature, ...expected } = reference;
    expect(result.context.headCid).toBe(canonicalCid(f.genesis.op));
    expect(result.operation.prev).toBe(reference.prev);
    expect(plain(result.operation)).toEqual(expected);
    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(result.context)).toBe(true);
    expect(Object.isFrozen(result.operation)).toBe(true);
    expect(Object.isFrozen(result.operation.rotationKeys)).toBe(true);
    expect(Object.isFrozen(result.operation.verificationMethods)).toBe(true);
    expect(Object.isFrozen(result.operation.services.atproto_pds)).toBe(true);
  });

  it('normalizes an authentic legacy genesis only after hashing its signed bytes', async () => {
    const f = await fixture();
    const legacy = await deprecatedSignCreate({ type: 'create', signingKey: f.signing.did(), recoveryKey: f.recovery.did(),
      handle: 'alice.test', service: 'pds.example', prev: null }, f.signing);
    const did = await didForCreateOp(legacy);
    const result = f.plan(legacy, { did });
    expect(result.tag).toBe('proposed');
    if (result.tag !== 'proposed') throw new Error('Expected a proposed legacy update');
    const reference = await createUpdateOp(legacy, f.signing, (current) => ({
      ...current, verificationMethods: { ...current.verificationMethods, atproto_kem: f.kem.did() },
    }));
    const { sig: _signature, ...expected } = reference;
    expect(result.context.headCid).toBe(canonicalCid(legacy));
    expect(result.context.headCid).not.toBe(canonicalCid(normalizeOp(legacy)));
    expect(result.operation.prev).toBe(reference.prev);
    expect(plain(result.operation)).toEqual(expected);
    expect(result.operation.rotationKeys).toEqual([f.recovery.did(), f.signing.did()]);
    expect(result.operation.alsoKnownAs).toEqual(['at://alice.test']);
    expect(result.operation.services.atproto_pds.endpoint).toBe(ORIGIN);
  });

  it('preserves supported methods, services, aliases and rotations', async () => {
    const f = await fixture();
    const head = await createUpdateOp(f.genesis.op, f.signing, (current) => ({
      ...current,
      verificationMethods: { ...current.verificationMethods, secondary: f.other.did() },
      services: { ...current.services, extra: { type: 'OtherService', endpoint: 'https://other.example/path' } },
      alsoKnownAs: [...current.alsoKnownAs, 'https://profile.example/alice'],
    }));
    const snapshot = JSON.stringify(head);
    const result = f.plan(head);
    expect(result.tag).toBe('proposed');
    if (result.tag !== 'proposed') throw new Error('Expected a proposed operation');
    expect(JSON.stringify(head)).toBe(snapshot);
    expect(result.operation.rotationKeys).toEqual(head.rotationKeys);
    expect(result.operation.alsoKnownAs).toEqual(head.alsoKnownAs);
    expect(result.operation.services.extra).toEqual({ type: 'OtherService', endpoint: 'https://other.example/path' });
    expect(result.operation.verificationMethods.secondary).toBe(f.other.did());
    expect(result.operation.verificationMethods.atproto_kem).toBe(f.kem.did());
    head.services.extra.endpoint = 'https://mutated.example';
    expect(result.operation.services.extra.endpoint).toBe('https://other.example/path');
  });

  it('distinguishes a matching captured key from a different key', async () => {
    const f = await fixture();
    const head = await createUpdateOp(f.genesis.op, f.signing, (current) => ({
      ...current, verificationMethods: { ...current.verificationMethods, atproto_kem: f.kem.did() },
    }));
    expect(f.plan(head).tag).toBe('matches');
    expect(f.plan(head, { kem: f.other.did() })).toEqual({ tag: 'blocked', reason: 'differentKem' });
    expect(f.plan({ ...head, verificationMethods: { ...head.verificationMethods, atproto_kem: null } }).tag).toBe('blocked');
  });

  it('rejects invalid captures and identity mismatches without changing input', async () => {
    const f = await fixture();
    for (const overrides of [
      { did: 'did:web:example.com' }, { did: 'did:plc:aaaaaaaaaaaaaaaaaaaaaaaa' },
      { incarnation: 'bad' }, { active: false }, { origin: 'http://pds.example' },
      { origin: 'https://pds.example/path' }, { origin: 'https://user@pds.example' },
      { signing: f.other.did() }, { rotation: f.other.did() }, { kem: f.signing.did() },
      { kem: 'did:key:zbad' },
    ]) expect(f.plan(f.genesis.op, overrides).tag).toBe('blocked');
    const update = await createUpdateOp(f.genesis.op, f.signing, (current) => current);
    const foreignHost = { ...update, services: { ...update.services, atproto_pds: {
      type: 'AtprotoPersonalDataServer', endpoint: 'https://other.example',
    } } };
    expect(f.plan(foreignHost)).toEqual({ tag: 'blocked', reason: 'identityMismatch' });
    expect(f.plan({ ...update, verificationMethods: { ...update.verificationMethods, atproto: f.other.did() } }).tag).toBe('blocked');
    expect(f.plan({ ...update, rotationKeys: [f.recovery.did()] }).tag).toBe('blocked');
    expect(f.plan({ ...update, type: 'plc_tombstone' }).tag).toBe('blocked');
  });

  it('keeps non-genesis DID and account provenance as caller assertions', async () => {
    const f = await fixture();
    const update = await createUpdateOp(f.genesis.op, f.signing, (current) => current);
    const assertedDid = 'did:plc:aaaaaaaaaaaaaaaaaaaaaaaa';
    const assertedIncarnation = 'abcdef0123456789abcdef0123456789';
    const result = f.plan(update, { did: assertedDid, incarnation: assertedIncarnation });
    expect(result.tag).toBe('proposed');
    if (result.tag !== 'proposed') throw new Error('Expected an advisory proposal');
    expect(result.context.assertedDid).toBe(assertedDid);
    expect(result.context.accountIncarnation).toBe(assertedIncarnation);
  });
});
