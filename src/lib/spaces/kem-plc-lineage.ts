import * as dagCbor from "@ipld/dag-cbor";
import {
  assureValidOp,
  type CompatibleOp,
  normalizeOp,
  validateOperationLog,
} from "@did-plc/lib";
import {
  type ParsedPlcHead,
  parsePlcHead,
  validSigningKey,
} from "./kem-plc-operation";
import { type KemPlcPlan, planKemPlcUpdate } from "./kem-plc-plan";
import { verifyPlcLineageSignature } from "./kem-plc-lineage-signature";

const MAX_OPERATIONS = 32;
const MAX_HISTORY_BYTES = 512 * 1024;
const MAX_KEYS_PER_OPERATION = 16;
const MAX_HISTORY_KEYS = 256;

export type LinkedKemPlcPlan =
  | Readonly<{ tag: "invalidInput" | "invalidLineage" }>
  | Readonly<
    { tag: "signatureLinked"; operationCount: number; plan: KemPlcPlan }
  >;

type CapturedOperation = Readonly<
  { parsed: ParsedPlcHead; operation: CompatibleOp }
>;

/**
 * Check a caller-supplied linear signature chain and plan from its last head.
 * This does not establish directory acceptance, canonicality or freshness. The
 * caller must authenticate current account state and a durable KEM secret and
 * independently establish the current head before any later identity action.
 * Intended for bounded offline use; it neither signs nor publishes operations.
 */
export async function planKemPlcFromLineage(
  operationJsons: unknown,
  assertedDid: unknown,
  accountIncarnation: unknown,
  active: unknown,
  pdsOrigin: unknown,
  repoSigningDidKey: unknown,
  rotationDidKey: unknown,
  kemDidKey: unknown,
): Promise<LinkedKemPlcPlan> {
  try {
    const texts = captureHistory(operationJsons);
    if (!texts) return invalid("invalidInput");
    const head = texts[texts.length - 1];
    const plan = planKemPlcUpdate(
      head,
      assertedDid,
      accountIncarnation,
      active,
      pdsOrigin,
      repoSigningDidKey,
      rotationDidKey,
      kemDidKey,
    );
    if (plan.tag === "blocked" && plan.reason === "invalidInput") {
      return invalid("invalidInput");
    }
    if (typeof assertedDid !== "string") return invalid("invalidInput");
    const captured: CapturedOperation[] = [];
    let keyCount = 0;
    for (const text of texts) {
      const parsed = parsePlcHead(text);
      if (!parsed) return invalid("invalidLineage");
      const keys = [
        ...parsed.normalized.rotationKeys,
        ...Object.values(parsed.normalized.verificationMethods),
      ];
      keyCount += keys.length;
      if (
        keys.length > MAX_KEYS_PER_OPERATION || keyCount > MAX_HISTORY_KEYS ||
        !keys.every(validSigningKey)
      ) return invalid("invalidLineage");
      // The strict parser has checked the exact schema; decode its canonical
      // bytes so async checks never observe a mutable caller-owned object.
      const operation = dagCbor.decode(parsed.originalBytes) as CompatibleOp;
      captured.push({ parsed, operation });
    }
    for (let index = 0; index < captured.length; index++) {
      const item = captured[index];
      const keys = index === 0
        ? item.parsed.normalized.rotationKeys
        : captured[index - 1].parsed.normalized.rotationKeys;
      await assureValidOp(normalizeOp(item.operation));
      if (!await verifyPlcLineageSignature(item.operation, keys)) {
        return invalid("invalidLineage");
      }
    }
    const document = await validateOperationLog(
      assertedDid,
      captured.map((item) => item.operation),
    );
    if (!document) return invalid("invalidLineage");
    return Object.freeze({
      tag: "signatureLinked",
      operationCount: captured.length,
      plan,
    });
  } catch {
    // PLC library errors can contain full operations; keep them out of logs.
    return invalid("invalidLineage");
  }
}

function captureHistory(value: unknown): readonly string[] | null {
  if (!Array.isArray(value)) return null;
  const length = value.length;
  if (!Number.isInteger(length) || length < 1 || length > MAX_OPERATIONS) {
    return null;
  }
  const texts: string[] = [];
  let totalBytes = 0;
  const encoder = new TextEncoder();
  for (let index = 0; index < length; index++) {
    const text: unknown = value[index];
    if (typeof text !== "string" || text.length > 65_536) return null;
    totalBytes += encoder.encode(text).byteLength;
    if (totalBytes > MAX_HISTORY_BYTES) return null;
    texts.push(text);
  }
  return Object.freeze(texts);
}

function invalid(tag: "invalidInput" | "invalidLineage"): LinkedKemPlcPlan {
  return Object.freeze({ tag });
}
