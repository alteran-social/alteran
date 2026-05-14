import { randomBytes } from '@noble/hashes/utils.js';
import { scryptAsync } from '@noble/hashes/scrypt.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

const SALT_BYTES = 16;
const KEY_LEN = 64;
const SCRYPT_OPTS = {
  N: 1 << 15, // Close to Node scrypt defaults while remaining worker-friendly
  r: 8,
  p: 1,
  dkLen: KEY_LEN,
};

async function derive(password: string, saltHex: string): Promise<string> {
  const salt = hexToBytes(saltHex);
  const key = await scryptAsync(password, salt, SCRYPT_OPTS);
  return bytesToHex(key);
}

export async function hashPassword(password: string): Promise<string> {
  const saltHex = bytesToHex(randomBytes(SALT_BYTES));
  const hashHex = await derive(password, saltHex);
  return `${saltHex}:${hashHex}`;
}

export async function verifyPassword(password: string, stored: string | null): Promise<boolean> {
  if (!stored) return false;
  const [saltHex, hashHex] = stored.split(':');
  if (!saltHex || !hashHex) return false;
  const candidate = await derive(password, saltHex);
  return constantTimeHexEquals(candidate, hashHex);
}

export async function rehashIfNeeded(password: string, stored: string | null): Promise<string | null> {
  if (!stored) return null;
  const [saltHex] = stored.split(':');
  if (!saltHex) return null;
  // Currently no adaptive parameters; placeholder for future upgrades.
  return null;
}

function constantTimeHexEquals(leftHex: string, rightHex: string): boolean {
  let left: Uint8Array;
  let right: Uint8Array;
  try {
    left = hexToBytes(leftHex);
    right = hexToBytes(rightHex);
  } catch {
    return false;
  }

  let diff = left.length ^ right.length;
  const length = Math.max(left.length, right.length);
  for (let i = 0; i < length; i++) {
    diff |= (left[i] ?? 0) ^ (right[i] ?? 0);
  }
  return diff === 0;
}
