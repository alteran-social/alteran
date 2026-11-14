import { P256Keypair } from '@atproto/crypto-spaces';
import { decapsulate, isP256DidKey } from '@atproto/space';
import type { Env } from '../../env';
import { resolveSecret } from '../secrets';

export type SpaceKemKey = {
  readonly publicDidKey: string;
  readonly deriveSharedSecret: (keyShare: string) => Uint8Array;
};

export type SpaceKemKeyResult =
  | { readonly tag: 'missing' }
  | { readonly tag: 'invalid' }
  | { readonly tag: 'unavailable' }
  | { readonly tag: 'ready'; readonly key: SpaceKemKey };

export async function loadSpaceKemKey(env: Env): Promise<SpaceKemKeyResult> {
  let configured: string | undefined;
  let signing: string | undefined;
  let rotation: string | undefined;
  try {
    configured = await resolveSecret(env.PDS_SPACE_KEM_KEY);
    if (configured === undefined || configured.trim() === '') return { tag: 'missing' };
    [signing, rotation] = await Promise.all([
      resolveSecret(env.REPO_SIGNING_KEY),
      resolveSecret(env.PDS_PLC_ROTATION_KEY),
    ]);
  } catch {
    return { tag: 'unavailable' };
  }

  const privateKey = decodePrivateKey(configured);
  if (!privateKey) return { tag: 'invalid' };
  for (const other of [signing, rotation]) {
    if (other === undefined || other.trim() === '') continue;
    const otherKey = decodeExistingPrivateKey(other);
    if (!otherKey || sameBytes(privateKey, otherKey)) return { tag: 'invalid' };
  }

  try {
    const keypair = await P256Keypair.import(privateKey, { exportable: false });
    return {
      tag: 'ready',
      key: {
        publicDidKey: keypair.did(),
        deriveSharedSecret: (keyShare) => {
          if (!isP256DidKey(keyShare)) throw new Error('Invalid Spaces KEM key share');
          try {
            return decapsulate(keypair, keyShare);
          } catch {
            throw new Error('Invalid Spaces KEM key share');
          }
        },
      },
    };
  } catch {
    return { tag: 'invalid' };
  }
}

function decodePrivateKey(value: string): Uint8Array | null {
  const text = value.trim();
  if (/^[0-9a-f]{64}$/i.test(text)) {
    return Uint8Array.from(text.match(/../g) ?? [], (byte) => Number.parseInt(byte, 16));
  }
  if (!/^[A-Za-z0-9+/]{43}=$/.test(text)) return null;
  try {
    const decoded = atob(text);
    if (decoded.length !== 32 || btoa(decoded) !== text) return null;
    return Uint8Array.from(decoded, (character) => character.charCodeAt(0));
  } catch {
    return null;
  }
}

function decodeExistingPrivateKey(value: string): Uint8Array | null {
  const text = value.trim();
  if (/^[0-9a-f]{64}$/i.test(text)) return decodePrivateKey(text);
  try {
    const decoded = atob(text.replace(/\s+/g, ''));
    if (decoded.length !== 32) return null;
    return Uint8Array.from(decoded, (character) => character.charCodeAt(0));
  } catch {
    return null;
  }
}

function sameBytes(first: Uint8Array, second: Uint8Array): boolean {
  let difference = 0;
  for (let index = 0; index < first.length; index++) difference |= first[index] ^ second[index];
  return difference === 0;
}
