import {
  createRecordMacHeaders, isP256DidKey, parseMacRequest,
  RECORD_MAC_PROFILE, verifyRecordMac,
} from '@atproto/space';
import type { SpaceKemKey } from './kem-key';
import { copyPlainRecord } from './plain-values';
import {
  captureRecordCid, captureRecordIdentity, copyResponseBytes, invalidMac,
  type SpaceRecordResponseIdentity,
} from './record-response-input';

const MAX_HEADER_LENGTH = 8192;
const EXPOSED = 'atproto-space-record, signature-input, signature';

export type SpaceRecordMacOptions = {
  readonly acceptSignature: string | null;
  /**
   * The caller authenticates this key as the repo's current KEM key. Its
   * derived secret is treated as borrowed; only the helper's copy is cleared.
   */
  readonly kemKey: SpaceKemKey | null;
  readonly requireMac: boolean;
};

export function recordResponseMacHeaders(
  uri: ReturnType<typeof captureRecordIdentity>['uri'],
  cid: ReturnType<typeof captureRecordCid>,
  input: SpaceRecordMacOptions,
): Record<string, string> {
  const options = copyPlainRecord(input, ['acceptSignature', 'kemKey', 'requireMac']);
  if (!options || typeof options.requireMac !== 'boolean' ||
    (options.acceptSignature !== null && typeof options.acceptSignature !== 'string')) throw invalidMac();
  const accept = options.acceptSignature as string | null;
  if (accept !== null && !validHeader(accept)) throw invalidMac();
  let request;
  try {
    request = parseMacRequest(accept ?? undefined, RECORD_MAC_PROFILE);
  } catch {
    throw invalidMac();
  }
  const headers: Record<string, string> = { vary: 'Accept-Signature' };
  if (!request) {
    if (options.requireMac) throw invalidMac();
    return headers;
  }
  const key = copyPlainRecord(options.kemKey, ['publicDidKey', 'deriveSharedSecret']);
  if (!key || typeof key.publicDidKey !== 'string' || key.publicDidKey.length > 256 ||
    !isP256DidKey(key.publicDidKey) || typeof key.deriveSharedSecret !== 'function' ||
    !isP256DidKey(request.keyShare)) throw invalidMac();
  let secret: Uint8Array | undefined;
  try {
    secret = copyResponseBytes(key.deriveSharedSecret(request.keyShare), 32, 32);
    Object.assign(headers, createRecordMacHeaders(uri, cid, { ...request, sharedSecret: secret }).headers);
    headers['access-control-expose-headers'] = EXPOSED;
    return headers;
  } catch {
    throw invalidMac();
  } finally {
    secret?.fill(0);
  }
}

/** Verify with the original request's trusted encapsulation, not response-provided keys. */
export function verifySpaceRecordResponseMac(
  identity: SpaceRecordResponseIdentity,
  cidValue: string,
  responseHeaders: Headers,
  encapsulation: { readonly keyShare: string; readonly sharedSecret: Uint8Array },
): boolean {
  let secret: Uint8Array | undefined;
  try {
    const { uri } = captureRecordIdentity(identity);
    const cid = captureRecordCid(cidValue);
    const input = copyPlainRecord(encapsulation, ['keyShare', 'sharedSecret']);
    if (!input || typeof input.keyShare !== 'string' || input.keyShare.length > 256 ||
      !isP256DidKey(input.keyShare) || !(responseHeaders instanceof Headers)) return false;
    secret = copyResponseBytes(input.sharedSecret, 32, 32);
    const headers = new Headers();
    for (const name of ['atproto-space-record', 'signature-input', 'signature']) {
      const value = Headers.prototype.get.call(responseHeaders, name);
      if (value === null || !validHeader(value)) return false;
      headers.set(name, value);
    }
    verifyRecordMac(uri, cid, { keyShare: input.keyShare, sharedSecret: secret, headers });
    return true;
  } catch {
    return false;
  } finally {
    secret?.fill(0);
  }
}

function validHeader(value: string): boolean {
  return value.length <= MAX_HEADER_LENGTH && /^[\x09\x20-\x7e]*$/.test(value);
}
