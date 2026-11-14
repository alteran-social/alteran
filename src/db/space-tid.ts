import { isValidTid } from '@atproto/syntax-spaces';
import { SpaceStorageError } from './space-types';

const ALPHABET = '234567abcdefghijklmnopqrstuvwxyz';

export function nextSpaceRevision(previous: string | null, now = Date.now()): string {
  if (previous !== null && !isValidTid(previous)) {
    throw new SpaceStorageError('InvalidRepoState', 'Invalid stored space revision');
  }
  let previousTime = 0n;
  if (previous) {
    for (const character of previous.slice(0, 11)) {
      previousTime = previousTime * 32n + BigInt(ALPHABET.indexOf(character));
    }
  }
  const currentTime = BigInt(now) * 1000n;
  let timestamp = currentTime > previousTime ? currentTime : previousTime + 1n;
  let encoded = '';
  while (timestamp > 0n) {
    encoded = ALPHABET[Number(timestamp % 32n)] + encoded;
    timestamp /= 32n;
  }
  if (encoded.length > 11) throw new SpaceStorageError('InvalidRepoState', 'Space revision overflow');
  const clock = crypto.getRandomValues(new Uint16Array(1))[0] & 1023;
  const revision = encoded.padStart(11, '2') + ALPHABET[clock >> 5] + ALPHABET[clock & 31];
  if (!isValidTid(revision)) throw new SpaceStorageError('InvalidRepoState', 'Space revision overflow');
  return revision;
}
