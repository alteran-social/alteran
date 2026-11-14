import { describe, it } from './helpers/bdd';
import { expect } from '@std/expect';
import { P256Keypair } from '@atproto/crypto-spaces';
import { encapsulate } from '@atproto/space';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import type { Env } from '../src/env';
import { loadSpaceKemKey } from '../src/lib/spaces/kem-key';

const PRIVATE_KEY = '62c3868357a464f8461d03aa0182c7cebcde841036aea7230ddc7339f1088346';
const PUBLIC_KEY = 'did:key:zDnaepxWioy4TQi6a94tSHKU4aqQkz6rksDiBfnuiGbwf4i5N';
const KEY_SHARE = 'did:key:zDnaexCXCyeFWXGnCUesVu6KucACKmUDm6i3M5fghGuy1jnch';
const CURVE_ORDER = 'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551';

function env(values: Partial<Env>): Env {
  return values as Env;
}

function base64(hex: string): string {
  return btoa(String.fromCharCode(...hexToBytes(hex)));
}

describe('Spaces KEM key', () => {
  it('loads the same public key from hex and canonical base64, including Secret Store bindings', async () => {
    const hex = await loadSpaceKemKey(env({ PDS_SPACE_KEM_KEY: PRIVATE_KEY }));
    const encoded = await loadSpaceKemKey(env({
      PDS_SPACE_KEM_KEY: { get: () => Promise.resolve(base64(PRIVATE_KEY)) },
    }));
    expect(hex.tag).toBe('ready');
    expect(encoded.tag).toBe('ready');
    if (hex.tag !== 'ready' || encoded.tag !== 'ready') throw new Error('Expected key');
    expect(hex.key.publicDidKey).toBe(PUBLIC_KEY);
    expect(encoded.key.publicDidKey).toBe(PUBLIC_KEY);
  });

  it('derives the reference HPKE secret using the configured key', async () => {
    const result = await loadSpaceKemKey(env({ PDS_SPACE_KEM_KEY: PRIVATE_KEY }));
    if (result.tag !== 'ready') throw new Error('Expected key');
    expect(bytesToHex(result.key.deriveSharedSecret(KEY_SHARE))).toBe(
      '2060e0558d1b34c10086bc137f849bb79ba59fcdc30544418e35c9cd301f0d0d',
    );
  });

  it('rejects invalid key material without returning it in errors', async () => {
    for (const invalid of [
      '00'.repeat(32),
      CURVE_ORDER,
      'ff'.repeat(32),
      'ab'.repeat(31),
      `${base64(PRIVATE_KEY).slice(0, -2)}B=`,
      `${PRIVATE_KEY} not-a-key`,
    ]) {
      const result = await loadSpaceKemKey(env({ PDS_SPACE_KEM_KEY: invalid }));
      expect(result).toEqual({ tag: 'invalid' });
      expect(JSON.stringify(result)).not.toContain(invalid);
    }
  });

  it('does not reuse the configured repository or PLC signing key', async () => {
    expect(await loadSpaceKemKey(env({
      PDS_SPACE_KEM_KEY: PRIVATE_KEY,
      REPO_SIGNING_KEY: base64(PRIVATE_KEY),
    }))).toEqual({ tag: 'invalid' });
    expect(await loadSpaceKemKey(env({
      PDS_SPACE_KEM_KEY: PRIVATE_KEY,
      PDS_PLC_ROTATION_KEY: PRIVATE_KEY,
    }))).toEqual({ tag: 'invalid' });
    expect(await loadSpaceKemKey(env({
      PDS_SPACE_KEM_KEY: PRIVATE_KEY,
      REPO_SIGNING_KEY: base64(PRIVATE_KEY).replace(/=$/, ''),
    }))).toEqual({ tag: 'invalid' });
  });

  it('accepts a distinct repository key encoded with whitespace and no padding', async () => {
    const signing = base64('01'.repeat(32)).replace(/=$/, '');
    const result = await loadSpaceKemKey(env({
      PDS_SPACE_KEM_KEY: PRIVATE_KEY,
      REPO_SIGNING_KEY: `${signing.slice(0, 20)}\n${signing.slice(20)}`,
    }));
    expect(result.tag).toBe('ready');
  });

  it('fails closed for unavailable secrets and missing configuration', async () => {
    expect(await loadSpaceKemKey(env({}))).toEqual({ tag: 'missing' });
    expect(await loadSpaceKemKey(env({ PDS_SPACE_KEM_KEY: { get: () => Promise.reject(new Error('secret')) } })))
      .toEqual({ tag: 'unavailable' });
  });

  it('keeps keypair export disabled and rejects invalid peer keys', async () => {
    const keypair = await P256Keypair.import(PRIVATE_KEY, { exportable: false });
    await expect(keypair.export()).rejects.toThrow('Private key is not exportable');
    const result = await loadSpaceKemKey(env({ PDS_SPACE_KEM_KEY: PRIVATE_KEY }));
    if (result.tag !== 'ready') throw new Error('Expected key');
    expect(() => result.key.deriveSharedSecret('did:key:invalid')).toThrow('Invalid Spaces KEM key share');
    const other = await P256Keypair.create();
    const exchange = await encapsulate(other.did() as `did:${string}:${string}`);
    expect(result.key.deriveSharedSecret(exchange.keyShare)).not.toEqual(exchange.sharedSecret);
  });
});
