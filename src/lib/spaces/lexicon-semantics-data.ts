import { isValidNsid } from "@atproto/syntax-spaces";
import type { SemanticCheck } from "./lexicon-semantics-values";

/** Check the supported JSON-like subset of the AT Protocol data model. */
export function checkLexiconDataModel(root: unknown): SemanticCheck {
  const pending: unknown[] = [root];
  let unsupported = false;
  while (pending.length) {
    const value = pending.pop();
    if (Array.isArray(value)) {
      for (const child of value) pending.push(child);
      continue;
    }
    if (typeof value !== "object" || value === null) continue;
    const object = value as Record<string, unknown>;
    const keys = Object.keys(object);
    if (Object.hasOwn(object, "$bytes") || Object.hasOwn(object, "$link")) {
      if (keys.length !== 1) return "invalid";
      const content = Object.hasOwn(object, "$bytes")
        ? object.$bytes
        : object.$link;
      if (typeof content !== "string") return "invalid";
      unsupported = true;
      continue;
    }
    if (Object.hasOwn(object, "$type")) {
      if (typeof object.$type !== "string") return "invalid";
      if (object.$type === "blob") {
        // Blob and CID representations require model-aware decoding.
        unsupported = true;
        continue;
      }
      const type = object.$type.split("#");
      if (
        type.length > 2 || !isValidNsid(type[0]) ||
        (type.length === 2 && (!type[1] || type[1] === "main"))
      ) return "unsupported";
    }
    for (const key of keys) {
      if (key.startsWith("$") && key !== "$type") unsupported = true;
      pending.push(object[key]);
    }
  }
  return unsupported ? "unsupported" : "valid";
}
