import * as dagCbor from '@ipld/dag-cbor';
import { parseDidKey, formatDidKey } from '@atproto/crypto-spaces';
import { isP256DidKey } from '@atproto/space';
import { parseUniqueIdentityJson } from './identity-json';
import { parseCanonicalRepoCid } from './repo-cid';

export type PlcService = Readonly<{ type: string; endpoint: string }>;
export type PlcOperation = Readonly<{
  type: 'plc_operation';
  rotationKeys: readonly string[];
  verificationMethods: Readonly<Record<string, string>>;
  alsoKnownAs: readonly string[];
  services: Readonly<Record<string, PlcService>>;
  prev: string | null;
}>;
export type ParsedPlcHead = Readonly<{ originalBytes: Uint8Array; normalized: PlcOperation }>;

const MAX_HEAD_CHARS = 65_536;
// P-256 and secp256k1 public keys supported here are much shorter than this.
const MAX_SUPPORTED_SIGNING_KEY_CHARS = 128;
const MAX_ROTATION_ORDER = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');
export const MAX_PLC_OPERATION_BYTES = 7_500;

/** Parse a signed head without authenticating its signature, DID or freshness. */
export function parsePlcHead(text: unknown): ParsedPlcHead | null {
  if (typeof text !== 'string' || text.length > MAX_HEAD_CHARS || !wellFormed(text) ||
    new TextEncoder().encode(text).byteLength > MAX_HEAD_CHARS) {
    return null;
  }
  const input = parseUniqueIdentityJson(text);
  if (!isRecord(input) || !Object.hasOwn(input, 'type') || !allStringsWellFormed(input)) return null;
  let originalBytes: Uint8Array;
  try {
    originalBytes = dagCbor.encode(input);
    if (originalBytes.byteLength > MAX_PLC_OPERATION_BYTES) return null;
  } catch {
    return null;
  }
  let normalized: PlcOperation | null = null;
  if (input.type === 'plc_operation') normalized = parseRegular(input);
  else if (input.type === 'create') normalized = parseLegacy(input);
  return normalized ? { originalBytes, normalized } : null;
}

function parseRegular(input: Record<string, unknown>): PlcOperation | null {
  if (!exactKeys(input, ['type', 'rotationKeys', 'verificationMethods', 'alsoKnownAs', 'services', 'prev', 'sig']) ||
    !validSignature(input.sig) || !validPrevious(input.prev)) return null;
  const rotationKeys = stringArray(input.rotationKeys);
  const alsoKnownAs = stringArray(input.alsoKnownAs);
  const verificationMethods = stringMap(input.verificationMethods);
  const services = serviceMap(input.services);
  if (!rotationKeys || rotationKeys.length < 1 || rotationKeys.length > 5 ||
    new Set(rotationKeys).size !== rotationKeys.length || !rotationKeys.every(validSigningKey) ||
    !alsoKnownAs || !verificationMethods || !services ||
    !Object.values(verificationMethods).every(validGenericDidKey)) return null;
  return { type: 'plc_operation', rotationKeys, alsoKnownAs, verificationMethods, services, prev: input.prev as string | null };
}

function parseLegacy(input: Record<string, unknown>): PlcOperation | null {
  if (!exactKeys(input, ['type', 'signingKey', 'recoveryKey', 'handle', 'service', 'prev', 'sig']) ||
    !validSignature(input.sig) || input.prev !== null || typeof input.signingKey !== 'string' ||
    typeof input.recoveryKey !== 'string' || !validSigningKey(input.signingKey) || !validSigningKey(input.recoveryKey) ||
    input.signingKey === input.recoveryKey || typeof input.handle !== 'string' || !input.handle ||
    typeof input.service !== 'string' || !input.service) return null;
  const handle = input.handle.startsWith('at://') ? input.handle :
    `at://${input.handle.replace('http://', '').replace('https://', '')}`;
  const endpoint = input.service.startsWith('http://') || input.service.startsWith('https://')
    ? input.service : `https://${input.service}`;
  const verificationMethods: Record<string, string> = Object.create(null);
  verificationMethods.atproto = input.signingKey;
  const services: Record<string, PlcService> = Object.create(null);
  services.atproto_pds = { type: 'AtprotoPersonalDataServer', endpoint };
  return { type: 'plc_operation', rotationKeys: [input.recoveryKey, input.signingKey],
    verificationMethods, alsoKnownAs: [handle], services, prev: null };
}

export function validSigningKey(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > MAX_SUPPORTED_SIGNING_KEY_CHARS) return false;
  try {
    const parsed = parseDidKey(value);
    return (parsed.jwtAlg === 'ES256' || parsed.jwtAlg === 'ES256K') &&
      formatDidKey(parsed.jwtAlg, parsed.keyBytes) === value;
  } catch {
    return false;
  }
}

export function validKemKey(value: unknown): value is string {
  return validSigningKey(value) && isP256DidKey(value);
}

function validGenericDidKey(value: string): boolean {
  // Non-local methods are retained using only did:key/base58btc syntax; this
  // does not establish a supported multicodec or authenticate the key.
  return /^did:key:z[1-9A-HJ-NP-Za-km-z]+$/.test(value);
}

function validPrevious(value: unknown): value is string | null {
  if (value === null) return true;
  const cid = parseCanonicalRepoCid(value);
  return typeof value === 'string' && cid?.toString() === value;
}

function validSignature(value: unknown): boolean {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(value)) return false;
  try {
    const binary = atob(value.replaceAll('-', '+').replaceAll('_', '/') + '==');
    if (binary.length !== 64 || btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '') !== value) {
      return false;
    }
    let first = 0n, second = 0n;
    for (let index = 0; index < 32; index++) {
      first = first * 256n + BigInt(binary.charCodeAt(index));
      second = second * 256n + BigInt(binary.charCodeAt(index + 32));
    }
    // The actual signer and curve still require verification against the prior operation.
    return first > 0n && first < MAX_ROTATION_ORDER && second > 0n && second <= MAX_ROTATION_ORDER / 2n;
  } catch {
    return false;
  }
}

function stringArray(value: unknown): string[] | null {
  return Array.isArray(value) && value.every((item) => typeof item === 'string' && item.length > 0)
    ? [...value] : null;
}

function stringMap(value: unknown): Record<string, string> | null {
  if (!isRecord(value)) return null;
  const result: Record<string, string> = Object.create(null);
  for (const [name, entry] of Object.entries(value)) {
    if (!name || name.startsWith('#') || typeof entry !== 'string' || !entry) return null;
    result[name] = entry;
  }
  return result;
}

function serviceMap(value: unknown): Record<string, PlcService> | null {
  if (!isRecord(value)) return null;
  const result: Record<string, PlcService> = Object.create(null);
  for (const [name, service] of Object.entries(value)) {
    if (!name || name.startsWith('#') || !isRecord(service) || !exactKeys(service, ['type', 'endpoint']) ||
      typeof service.type !== 'string' || !service.type || typeof service.endpoint !== 'string' || !service.endpoint) {
      return null;
    }
    result[name] = { type: service.type, endpoint: service.endpoint };
  }
  return result;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === expected.length && keys.every((key) => expected.includes(key));
}

function allStringsWellFormed(root: unknown): boolean {
  const pending = [root];
  while (pending.length) {
    const value = pending.pop();
    if (typeof value === 'string') {
      if (!wellFormed(value)) return false;
    } else if (Array.isArray(value)) {
      for (const child of value) pending.push(child);
    } else if (isRecord(value)) {
      for (const [key, child] of Object.entries(value)) {
        if (!wellFormed(key)) return false;
        pending.push(child);
      }
    }
  }
  return true;
}

function wellFormed(value: string): boolean {
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(++index);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
    } else if (code >= 0xdc00 && code <= 0xdfff) return false;
  }
  return true;
}
