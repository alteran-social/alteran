import { randomBytes } from '@noble/hashes/utils.js';

const APP_PASSWORD_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';
const APP_PASSWORD_GROUPS = 4;
const APP_PASSWORD_GROUP_LEN = 4;

export function generateAppPassword(): string {
  const bytes = randomBytes(APP_PASSWORD_GROUPS * APP_PASSWORD_GROUP_LEN);
  const chars = Array.from(bytes, (byte) =>
    APP_PASSWORD_ALPHABET[byte % APP_PASSWORD_ALPHABET.length]
  );
  const groups: string[] = [];
  for (let i = 0; i < APP_PASSWORD_GROUPS; i++) {
    const start = i * APP_PASSWORD_GROUP_LEN;
    groups.push(chars.slice(start, start + APP_PASSWORD_GROUP_LEN).join(''));
  }
  return groups.join('-');
}

export function isAppPasswordFormat(value: string): boolean {
  return /^[a-z2-7]{4}(?:-[a-z2-7]{4}){3}$/.test(value);
}
