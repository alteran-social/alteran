import { randomBytes } from '@noble/hashes/utils.js';

// RFC 4648 base32 lowercase alphabet (no 0, 1, 8, 9); the reference PDS
// generates 16 random characters split into four dash-separated groups.
const ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';
const FORMAT_RE = /^[a-z2-7]{4}-[a-z2-7]{4}-[a-z2-7]{4}-[a-z2-7]{4}$/;

export function generateAppPasswordSecret(): string {
  const bytes = randomBytes(16);
  const chars: string[] = [];
  for (let i = 0; i < 16; i++) {
    chars.push(ALPHABET[bytes[i] % ALPHABET.length]);
  }
  return `${chars.slice(0, 4).join('')}-${chars.slice(4, 8).join('')}-${chars.slice(8, 12).join('')}-${chars.slice(12, 16).join('')}`;
}

export function isAppPasswordFormat(value: string): boolean {
  return FORMAT_RE.test(value);
}
