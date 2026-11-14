import { CID } from "multiformats/cid";
import { base32 } from "multiformats/bases/base32";
import { base36 } from "multiformats/bases/base36";
import { base58btc } from "multiformats/bases/base58";

const decoder = base32.decoder.or(base36.decoder).or(base58btc.decoder);

/** AT Protocol repo blocks use canonical CIDv1 DAG-CBOR with SHA-256. */
export function isCanonicalRepoCid(cid: CID | null): cid is CID {
  if (!cid) return false;
  const bytes = cid.bytes;
  return bytes.length === 36 && bytes[0] === 0x01 && bytes[1] === 0x71 &&
    bytes[2] === 0x12 && bytes[3] === 0x20 &&
    cid.multihash.digest.byteLength === 32;
}

export function parseCanonicalRepoCid(value: unknown): CID | null {
  if (typeof value !== "string" || value.length > 128) return null;
  try {
    const bytes = decoder.decode(value);
    if (
      bytes.length !== 36 || bytes[0] !== 0x01 || bytes[1] !== 0x71 ||
      bytes[2] !== 0x12 || bytes[3] !== 0x20
    ) return null;
    const cid = CID.decode(bytes);
    return isCanonicalRepoCid(cid) ? cid : null;
  } catch {
    return null;
  }
}
