import { expect } from '@std/expect';
import { describe, it } from './helpers/bdd';
import { P256Keypair, Secp256k1Keypair } from '@atproto/crypto-spaces';
import { createOp, createUpdateOp } from '@did-plc/lib';
import { planKemPlcUpdate } from '../src/lib/spaces/kem-plc-plan';

async function fixture() {
  const signing = await Secp256k1Keypair.create();
  const kem = await P256Keypair.create();
  const origin = 'https://pds.example';
  const genesis = await createOp({ signingKey: signing.did(), rotationKeys: [signing.did()],
    handle: 'alice.test', pds: origin, signer: signing });
  const head = await createUpdateOp(genesis.op, signing, (operation) => operation);
  const plan = (input: unknown) => planKemPlcUpdate(JSON.stringify(input), genesis.did,
    '1234567890abcdef1234567890abcdef', true, origin, signing.did(), signing.did(), kem.did());
  return { signing, kem, head, plan };
}

describe('KEM PLC incoming candidate limits', () => {
  it('allows a tenth method, blocks an eleventh, and leaves matching heads alone', async () => {
    const f = await fixture();
    const methods = (count: number) => ({ ...f.head.verificationMethods,
      ...Object.fromEntries(Array.from({ length: count }, (_, index) => [`extra${index}`, f.signing.did()])) });
    const nine = { ...f.head, verificationMethods: methods(8) };
    const ten = { ...f.head, verificationMethods: methods(9) };
    expect(f.plan(nine).tag).toBe('proposed');
    expect(f.plan(ten)).toEqual({ tag: 'blocked', reason: 'serverLimit' });
    expect(f.plan({ ...nine, verificationMethods: { ...nine.verificationMethods, atproto_kem: f.kem.did() } }).tag)
      .toBe('matches');
    expect(f.plan({ ...ten, verificationMethods: { ...ten.verificationMethods, atproto_kem: f.kem.did() } }).tag)
      .toBe('matches');
  });

  it('bounds alias counts and lengths and rejects duplicate aliases', async () => {
    const f = await fixture();
    const aliases = Array.from({ length: 11 }, (_, index) => `at://alias${index}.example`);
    const prefix = 'at://alias.example/';
    const alias = (length: number) => prefix + 'x'.repeat(length - prefix.length);
    expect(f.plan({ ...f.head, alsoKnownAs: aliases.slice(0, 10) }).tag).toBe('proposed');
    expect(f.plan({ ...f.head, alsoKnownAs: aliases })).toEqual({ tag: 'blocked', reason: 'serverLimit' });
    expect(f.plan({ ...f.head, alsoKnownAs: [aliases[0], aliases[0]] }))
      .toEqual({ tag: 'blocked', reason: 'serverLimit' });
    expect(f.plan({ ...f.head, alsoKnownAs: [alias(258)] }).tag).toBe('proposed');
    expect(f.plan({ ...f.head, alsoKnownAs: [alias(259)] })).toEqual({ tag: 'blocked', reason: 'serverLimit' });
  });

  it('bounds service counts, IDs, types and endpoints', async () => {
    const f = await fixture();
    const extra = { type: 'OtherService', endpoint: 'https://other.example' };
    const services = (count: number) => ({ ...f.head.services,
      ...Object.fromEntries(Array.from({ length: count }, (_, index) => [`service${index}`, extra])) });
    const withService = (id: string, type: string, endpoint: string) => ({ ...f.head,
      services: { ...f.head.services, [id]: { type, endpoint } } });
    const prefix = 'https://other.example/';
    expect(f.plan({ ...f.head, services: services(9) }).tag).toBe('proposed');
    expect(f.plan({ ...f.head, services: services(10) })).toEqual({ tag: 'blocked', reason: 'serverLimit' });
    expect(f.plan(withService('s'.repeat(32), extra.type, extra.endpoint)).tag).toBe('proposed');
    expect(f.plan(withService('s'.repeat(33), extra.type, extra.endpoint)))
      .toEqual({ tag: 'blocked', reason: 'serverLimit' });
    expect(f.plan(withService('extra', 't'.repeat(256), extra.endpoint)).tag).toBe('proposed');
    expect(f.plan(withService('extra', 't'.repeat(257), extra.endpoint)))
      .toEqual({ tag: 'blocked', reason: 'serverLimit' });
    expect(f.plan(withService('extra', extra.type, prefix + 'x'.repeat(512 - prefix.length))).tag).toBe('proposed');
    expect(f.plan(withService('extra', extra.type, prefix + 'x'.repeat(513 - prefix.length))))
      .toEqual({ tag: 'blocked', reason: 'serverLimit' });
  });

  it('bounds method IDs and did:key lengths only for a proposed update', async () => {
    const f = await fixture();
    const key = (length: number) => 'did:key:z' + '2'.repeat(length - 'did:key:z'.length);
    const withMethod = (id: string, value: string, matching = false) => ({ ...f.head,
      verificationMethods: { ...f.head.verificationMethods, [id]: value,
        ...(matching ? { atproto_kem: f.kem.did() } : {}) } });
    expect(f.plan(withMethod('m'.repeat(32), f.signing.did())).tag).toBe('proposed');
    expect(f.plan(withMethod('m'.repeat(33), f.signing.did())))
      .toEqual({ tag: 'blocked', reason: 'serverLimit' });
    expect(f.plan(withMethod('extra', key(256))).tag).toBe('proposed');
    expect(f.plan(withMethod('extra', key(257)))).toEqual({ tag: 'blocked', reason: 'serverLimit' });
    expect(f.plan(withMethod('extra', key(257), true)).tag).toBe('matches');
    expect(f.plan(withMethod('m'.repeat(33), f.signing.did(), true)).tag).toBe('matches');
  });

  it('does not apply present-day alias or service limits to matching captures', async () => {
    const f = await fixture();
    const extra = { type: 't'.repeat(257), endpoint: 'https://other.example/' + 'x'.repeat(513) };
    const matching = { ...f.head,
      verificationMethods: { ...f.head.verificationMethods, atproto_kem: f.kem.did() },
      services: { ...f.head.services, ['s'.repeat(33)]: extra },
      alsoKnownAs: ['at://duplicate.example', 'at://duplicate.example', 'x'.repeat(259)] };
    expect(f.plan(matching).tag).toBe('matches');
  });
});
