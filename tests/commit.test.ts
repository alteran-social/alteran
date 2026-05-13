import { describe, test, expect } from 'bun:test';
import {
  createCommit,
  signCommit,
  verifyCommit,
  commitCid,
  generateTid,
  isValidTid,
} from '../src/lib/commit';
import { CID } from 'multiformats/cid';
import { Secp256k1Keypair } from '@atproto/crypto';
import { RepoManager } from '../src/services/repo-manager';
import { makeEnv } from './helpers/env';

async function withFixedDateNow<T>(value: number, fn: () => Promise<T> | T): Promise<T> {
  const originalNow = Date.now;
  Date.now = () => value;
  try {
    return await fn();
  } finally {
    Date.now = originalNow;
  }
}

describe('Commit Structure & Signing', () => {
  test('should emit fixed-width TIDs for small clocks and full clock id range', async () => {
    const originalRandom = Math.random;
    Math.random = () => 0.999999999;
    try {
      await withFixedDateNow(0, () => {
        const tid = generateTid();
        expect(tid).toBe('22222222223zz');
        expect(isValidTid(tid)).toBe(true);
        expect(tid.length).toBe(13);
      });
    } finally {
      Math.random = originalRandom;
    }
  });

  test('should create a commit', () => {
    const did = 'did:plc:test123';
    const mstRoot = CID.parse('bafyreigbtj4x7ip5legnfznufuopl4sg4knzc2cof6duas4b3q2fy6swua');
    const rev = '3jzfcijpj2z2a';

    const commit = createCommit(did, mstRoot, rev);

    expect(commit.did).toBe(did);
    expect(commit.version).toBe(3);
    expect(commit.data.toString()).toBe(mstRoot.toString());
    expect(commit.rev).toBe(rev);
    expect(commit.prev).toBeNull();
  });

  test('should generate valid TID', () => {
    const tid = generateTid();
    expect(isValidTid(tid)).toBe(true);
    expect(tid.length).toBe(13);
  });

  test('should reject non-ATProto TID syntax', () => {
    expect(isValidTid('3jzfcijpj2z2a')).toBe(true);
    expect(isValidTid('zzzzzzzzzzzzz')).toBe(false);
    expect(isValidTid('3jzfcijpj2z2')).toBe(false);
  });

  test('should generate unique ordered TIDs within the same millisecond', async () => {
    await withFixedDateNow(Date.now(), () => {
      const tids = Array.from({ length: 32 }, () => generateTid());
      expect(new Set(tids).size).toBe(tids.length);
      expect(tids).toEqual([...tids].sort());
      for (const tid of tids) expect(isValidTid(tid)).toBe(true);
    });
  });

  test('should keep generated TIDs monotonic when the clock moves backwards', () => {
    const originalNow = Date.now;
    const now = Date.now();
    const times = [now, now - 60_000];
    Date.now = () => times.shift() ?? now - 60_000;
    try {
      const first = generateTid();
      const second = generateTid();
      expect(second > first).toBe(true);
      expect(isValidTid(first)).toBe(true);
      expect(isValidTid(second)).toBe(true);
    } finally {
      Date.now = originalNow;
    }
  });

  test('repo creates in the same millisecond receive distinct ordered rkeys and revs', async () => {
    const env = await makeEnv();
    const repo = new RepoManager(env);

    await withFixedDateNow(Date.now(), async () => {
      const first = await repo.createRecord('app.bsky.feed.post', {
        $type: 'app.bsky.feed.post',
        text: 'first',
        createdAt: '2026-05-13T00:00:00.000Z',
      });
      const second = await repo.createRecord('app.bsky.feed.post', {
        $type: 'app.bsky.feed.post',
        text: 'second',
        createdAt: '2026-05-13T00:00:00.001Z',
      });

      const firstRkey = first.uri.split('/').at(-1);
      const secondRkey = second.uri.split('/').at(-1);

      expect(firstRkey).toBeDefined();
      expect(secondRkey).toBeDefined();
      expect(firstRkey).not.toBe(secondRkey);
      expect(secondRkey! > firstRkey!).toBe(true);
      expect(first.rev).not.toBe(second.rev);
      expect(second.rev > first.rev).toBe(true);
      expect(isValidTid(firstRkey!)).toBe(true);
      expect(isValidTid(secondRkey!)).toBe(true);
      expect(isValidTid(first.rev)).toBe(true);
      expect(isValidTid(second.rev)).toBe(true);
    });
  });

  test('should sign and verify commit', async () => {
    // Generate test keypair (secp256k1)
    const keypair = await Secp256k1Keypair.create({ exportable: true });
    const privBytes = await keypair.export();
    const privateKeyHex = Array.from(privBytes).map(b => b.toString(16).padStart(2, '0')).join('');
    const didKey = keypair.did();

    // Create and sign commit
    const did = 'did:plc:test123';
    const mstRoot = CID.parse('bafyreigbtj4x7ip5legnfznufuopl4sg4knzc2cof6duas4b3q2fy6swua');
    const rev = generateTid();

    const commit = createCommit(did, mstRoot, rev);
    const signedCommit = await signCommit(commit, privateKeyHex);

    // Verify signature
    const isValid = await verifyCommit(signedCommit, didKey);
    expect(isValid).toBe(true);
  });

  test('should calculate deterministic commit CID', async () => {
    const keypair = await Secp256k1Keypair.create({ exportable: true });
    const privBytes = await keypair.export();
    const privateKeyHex = Array.from(privBytes).map(b => b.toString(16).padStart(2, '0')).join('');

    const did = 'did:plc:test123';
    const mstRoot = CID.parse('bafyreigbtj4x7ip5legnfznufuopl4sg4knzc2cof6duas4b3q2fy6swua');
    const rev = '3jzfcijpj2z2a';

    const commit1 = createCommit(did, mstRoot, rev);
    const signed1 = await signCommit(commit1, privateKeyHex);
    const cid1 = await commitCid(signed1);

    const commit2 = createCommit(did, mstRoot, rev);
    const signed2 = await signCommit(commit2, privateKeyHex);
    const cid2 = await commitCid(signed2);

    // CIDs should be the same for identical commits
    expect(cid1.toString()).toBe(cid2.toString());
  });

  test('should reject invalid signature', async () => {
    const keypair1 = await Secp256k1Keypair.create({ exportable: true });
    const keypair2 = await Secp256k1Keypair.create({ exportable: true });
    const priv1Bytes = await keypair1.export();
    const privateKey1Hex = Array.from(priv1Bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    const wrongDid = keypair2.did();

    const did = 'did:plc:test123';
    const mstRoot = CID.parse('bafyreigbtj4x7ip5legnfznufuopl4sg4knzc2cof6duas4b3q2fy6swua');
    const rev = generateTid();

    const commit = createCommit(did, mstRoot, rev);
    const signedCommit = await signCommit(commit, privateKey1Hex);

    // Verify with wrong public key should fail
    const isValid = await verifyCommit(signedCommit, wrongDid);
    expect(isValid).toBe(false);
  });
});
