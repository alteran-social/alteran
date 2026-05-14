import { CID } from 'multiformats/cid';
import * as dagCbor from '@ipld/dag-cbor';
import { sha256 } from 'multiformats/hashes/sha2';
import { Secp256k1Keypair, verifySignature } from '@atproto/crypto';
import { ServerMisconfigured } from './errors';

/**
 * AT Protocol Commit Structure
 *
 * A commit represents a snapshot of the repository at a specific revision.
 * It includes:
 * - did: The DID of the repository owner
 * - version: Protocol version (currently 3)
 * - data: CID of the MST root
 * - rev: Revision number (TID format)
 * - prev: CID of the previous commit (null for first commit)
 * - sig: secp256k1 signature over the commit data (64-byte compact)
 */

export interface CommitData {
  did: string;
  version: number;
  data: CID; // MST root CID
  rev: string; // TID format revision
  prev: CID | null; // Previous commit CID
}

export interface SignedCommit extends CommitData {
  sig: Uint8Array;
}

/**
 * Create a commit object
 */
export function createCommit(
  did: string,
  mstRoot: CID,
  rev: string,
  prev: CID | null = null,
): CommitData {
  return {
    did,
    version: 3,
    data: mstRoot,
    rev,
    prev,
  };
}

/**
 * Sign a commit with secp256k1 private key
 */
export async function signCommit(
  commit: CommitData,
  privateKey: string,
): Promise<SignedCommit> {
  // Encode commit to CBOR for signing
  const commitBytes = dagCbor.encode(commit);

  // Accept hex (preferred) or base64 input for the 32-byte secp256k1 private key
  const cleaned = privateKey.trim();
  let keypair: Secp256k1Keypair;
  if (/^[0-9a-fA-F]{64}$/.test(cleaned)) {
    keypair = await Secp256k1Keypair.import(cleaned);
  } else {
    // try base64
    try {
      const bin = atob(cleaned.replace(/\s+/g, ''));
      const priv = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) priv[i] = bin.charCodeAt(i);
      keypair = await Secp256k1Keypair.import(priv);
    } catch {
      throw new ServerMisconfigured('Invalid REPO_SIGNING_KEY format: expected 32-byte hex or base64');
    }
  }

  const signature = await keypair.sign(new Uint8Array(commitBytes as unknown as Uint8Array));

  return {
    ...commit,
    sig: signature,
  };
}

/**
 * Verify a signed commit
 */
export async function verifyCommit(
  signedCommit: SignedCommit,
  didKey: string,
): Promise<boolean> {
  try {
    // Extract commit data (without signature)
    const { sig, ...commit } = signedCommit;
    const commitBytes = dagCbor.encode(commit);
    return verifySignature(didKey, new Uint8Array(commitBytes as unknown as Uint8Array), sig);
  } catch (error) {
    console.error('Commit verification failed:', error);
    return false;
  }
}

/**
 * Calculate CID for a signed commit
 */
export async function commitCid(signedCommit: SignedCommit): Promise<CID> {
  const bytes = dagCbor.encode(signedCommit);
  const hash = await sha256.digest(bytes);
  return CID.create(1, dagCbor.code, hash);
}

/**
 * Serialize signed commit to bytes
 */
export function serializeCommit(signedCommit: SignedCommit): Uint8Array {
  return dagCbor.encode(signedCommit);
}

/**
 * Deserialize commit from bytes
 */
export function deserializeCommit(bytes: Uint8Array): SignedCommit {
  return dagCbor.decode(bytes) as SignedCommit;
}

const SORTABLE_BASE32_CHARS = '234567abcdefghijklmnopqrstuvwxyz';
let lastTidTimestamp = 0;
let tidClockId: number | undefined;

function sortableBase32Encode(value: number): string {
  let encoded = '';
  let remaining = value;

  while (remaining > 0) {
    encoded = SORTABLE_BASE32_CHARS[remaining % 32] + encoded;
    remaining = Math.floor(remaining / 32);
  }

  return encoded;
}

function getTidClockId(): number {
  tidClockId ??= Math.floor(Math.random() * 1024);
  return tidClockId;
}

export function resetTidStateForTests(): void {
  lastTidTimestamp = 0;
  tidClockId = undefined;
}

/**
 * Generate an ATProto Timestamp Identifier for use as a record key or revision.
 *
 * The timestamp portion is microsecond-precision and monotonically increases
 * even when JavaScript only exposes millisecond time or the system clock moves
 * backwards.
 */
export function generateTid(): string {
  const nowMicros = Date.now() * 1000;
  const timestamp = Math.max(nowMicros, lastTidTimestamp + 1);
  lastTidTimestamp = timestamp;

  const timestampPart = sortableBase32Encode(timestamp).padStart(11, '2');
  const clockPart = sortableBase32Encode(getTidClockId()).padStart(2, '2');
  return `${timestampPart}${clockPart}`;
}

/**
 * Validate TID format
 */
export function isValidTid(tid: string): boolean {
  return /^[234567abcdefghij][234567abcdefghijklmnopqrstuvwxyz]{12}$/.test(tid);
}
