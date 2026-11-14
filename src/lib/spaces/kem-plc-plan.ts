import * as dagCbor from '@ipld/dag-cbor';
import { sha256 } from '@noble/hashes/sha2.js';
import { base32 } from 'multiformats/bases/base32';
import { CID } from 'multiformats/cid';
import { create as createDigest } from 'multiformats/hashes/digest';
import { parsePlcHead, validKemKey, validSigningKey, type PlcOperation, type PlcService } from './kem-plc-operation';
import { incomingCandidateError } from './kem-plc-candidate';

export type KemPlcPlanContext = Readonly<{
  assertedDid: string;
  accountIncarnation: string;
  pdsOrigin: string;
  repoSigningDidKey: string;
  rotationDidKey: string;
  kemDidKey: string;
  headCid: string;
}>;

export type KemPlcPlan =
  | Readonly<{ tag: 'blocked'; reason: 'invalidInput' | 'invalidHead' | 'identityMismatch' | 'differentKem' | 'tooLarge' | 'serverLimit' }>
  | Readonly<{ tag: 'matches'; context: KemPlcPlanContext }>
  | Readonly<{ tag: 'proposed'; context: KemPlcPlanContext; operation: PlcOperation }>;

type BlockedReason = Extract<KemPlcPlan, { tag: 'blocked' }>['reason'];

/**
 * Plan from a caller-asserted signed head and independently captured identity.
 * The caller must authenticate the DID-anchored chain and current head, active
 * account, controlled host and a durable, distinct, backed-up KEM secret, then
 * recheck them before any later action. Public keys cannot prove that private
 * scalars on different curves are distinct. A PLC recovery may supersede the
 * captured head. Extra verification methods are preserved after syntax checks,
 * without cryptographic validation. This function neither verifies the
 * signature nor signs, publishes or migrates data.
 * Callers decoding bytes must reject invalid UTF-8 before supplying JSON text.
 */
export function planKemPlcUpdate(
  signedHeadJson: unknown,
  assertedDid: unknown,
  accountIncarnation: unknown,
  active: unknown,
  pdsOrigin: unknown,
  repoSigningDidKey: unknown,
  rotationDidKey: unknown,
  kemDidKey: unknown,
): KemPlcPlan {
  if (typeof signedHeadJson !== 'string' || typeof assertedDid !== 'string' ||
    !/^did:plc:[a-z2-7]{24}$/.test(assertedDid) || typeof accountIncarnation !== 'string' ||
    !/^[0-9a-f]{32}$/.test(accountIncarnation) || active !== true || !validOrigin(pdsOrigin) ||
    !validSigningKey(repoSigningDidKey) || !validSigningKey(rotationDidKey) || !validKemKey(kemDidKey) ||
    kemDidKey === repoSigningDidKey || kemDidKey === rotationDidKey) return blocked('invalidInput');
  const head = parsePlcHead(signedHeadJson);
  if (!head) return blocked('invalidHead');
  const digest = sha256(head.originalBytes);
  const headCid = CID.createV1(dagCbor.code, createDigest(0x12, digest)).toString();
  // A genesis head has enough information to check the asserted DID itself.
  if (head.normalized.prev === null && `did:plc:${base32.encode(digest).slice(1, 25)}` !== assertedDid) {
    return blocked('identityMismatch');
  }
  const methods = head.normalized.verificationMethods;
  const service = head.normalized.services.atproto_pds;
  if (!Object.hasOwn(methods, 'atproto') || methods.atproto !== repoSigningDidKey ||
    !head.normalized.rotationKeys.includes(rotationDidKey) || !service ||
    service.type !== 'AtprotoPersonalDataServer' || !sameOrigin(service.endpoint, pdsOrigin)) {
    return blocked('identityMismatch');
  }
  const context: KemPlcPlanContext = Object.freeze({ assertedDid, accountIncarnation, pdsOrigin,
    repoSigningDidKey, rotationDidKey, kemDidKey, headCid });
  if (Object.hasOwn(methods, 'atproto_kem')) {
    if (!validKemKey(methods.atproto_kem)) return blocked('invalidHead');
    return methods.atproto_kem === kemDidKey ? Object.freeze({ tag: 'matches', context }) : blocked('differentKem');
  }
  const operation = captureOperation(head.normalized, headCid, kemDidKey);
  try {
    const error = incomingCandidateError(operation);
    if (error) return blocked(error);
  } catch {
    return blocked('invalidHead');
  }
  return Object.freeze({ tag: 'proposed', context, operation });
}

function captureOperation(head: PlcOperation, previous: string, kemDidKey: string): PlcOperation {
  const verificationMethods: Record<string, string> = Object.create(null);
  for (const [name, value] of Object.entries(head.verificationMethods)) verificationMethods[name] = value;
  verificationMethods.atproto_kem = kemDidKey;
  const services: Record<string, PlcService> = Object.create(null);
  for (const [name, service] of Object.entries(head.services)) {
    services[name] = Object.freeze({ type: service.type, endpoint: service.endpoint });
  }
  return Object.freeze({ type: 'plc_operation', prev: previous,
    rotationKeys: Object.freeze([...head.rotationKeys]), alsoKnownAs: Object.freeze([...head.alsoKnownAs]),
    verificationMethods: Object.freeze(verificationMethods), services: Object.freeze(services) });
}

function validOrigin(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > 2048 || !value.startsWith('https://')) return false;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && !url.username && !url.password && url.origin === value &&
      url.pathname === '/' && !url.search && !url.hash;
  } catch {
    return false;
  }
}

function sameOrigin(endpoint: string, expectedOrigin: string): boolean {
  try {
    const url = new URL(endpoint);
    return url.protocol === 'https:' && !url.username && !url.password && url.origin === expectedOrigin &&
      url.pathname === '/' && !url.search && !url.hash &&
      (url.href === url.origin || url.href === `${url.origin}/`);
  } catch {
    return false;
  }
}

function blocked(reason: BlockedReason): KemPlcPlan {
  return Object.freeze({ tag: 'blocked', reason });
}
