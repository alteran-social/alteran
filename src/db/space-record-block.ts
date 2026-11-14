import * as dagCbor from "@ipld/dag-cbor";
import { sha256 } from "@noble/hashes/sha2.js";
import { CID } from "multiformats/cid";
import { create as createDigest } from "multiformats/hashes/digest";
import { checkRecordCborBounds } from "../lib/spaces/record-cbor-bounds";
import { verifySpaceRecordDataModel } from "./space-verify-record";

/** Check the canonical record representation and CID used by Space writes. */
export function validSpaceRecordBlock(
  collection: string,
  claimedCid: string,
  bytes: Uint8Array,
): boolean {
  if (checkRecordCborBounds(bytes) !== "valid") return false;
  try {
    const value: unknown = dagCbor.decode(bytes);
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      return false;
    }
    const prototype = Object.getPrototypeOf(value);
    if (
      (prototype !== Object.prototype && prototype !== null) ||
      !Object.hasOwn(value, "$type") ||
      (value as Record<string, unknown>).$type !== collection
    ) return false;
    if (verifySpaceRecordDataModel(value) !== "valid") return false;
    const canonical = dagCbor.encode(value);
    if (
      canonical.length !== bytes.length ||
      canonical.some((byte, index) => byte !== bytes[index])
    ) return false;
    return CID.createV1(dagCbor.code, createDigest(0x12, sha256(bytes)))
      .toString() === claimedCid;
  } catch {
    return false;
  }
}
