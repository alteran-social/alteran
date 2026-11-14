import * as dagCbor from "@ipld/dag-cbor";
import { verifySignature } from "@atproto/crypto-spaces";
import type { CompatibleOp } from "@did-plc/lib";

/** Verify the original unsigned bytes with any authorized, low-S signer. */
export async function verifyPlcLineageSignature(
  operation: CompatibleOp,
  rotationKeys: readonly string[],
): Promise<boolean> {
  const { sig, ...unsigned } = operation;
  let bytes: Uint8Array;
  let signature: Uint8Array;
  try {
    bytes = dagCbor.encode(unsigned);
    const raw = atob(sig.replaceAll("-", "+").replaceAll("_", "/") + "==");
    signature = Uint8Array.from(raw, (character) => character.charCodeAt(0));
    if (signature.length !== 64) return false;
  } catch {
    return false;
  }
  for (const key of rotationKeys) {
    try {
      if (
        await verifySignature(key, bytes, signature, {
          allowMalleableSig: false,
        })
      ) return true;
    } catch {
      // A signature may be outside this curve's range but valid for a later key.
    }
  }
  return false;
}
