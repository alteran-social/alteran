const MAX_DEPTH = 64;
const MAX_NODES = 50_000;
const MAX_STRING_BYTES = 1024 * 1024;
const encoder = new TextEncoder();

export type CopiedLexicon =
  | { readonly tag: "copied"; readonly value: unknown }
  | { readonly tag: "invalid" }
  | { readonly tag: "unsupported" };

/** Snapshot JSON-like data before passing it to the structural validator. */
export function copyLexicon(value: unknown): CopiedLexicon {
  let copy: unknown;
  let count = 0;
  let bytes = 0;
  const seen = new WeakSet<object>();
  const pending: Array<{
    readonly value: unknown;
    readonly depth: number;
    readonly assign: (value: unknown) => void;
  }> = [{ value, depth: 0, assign: (result) => copy = result }];

  function countString(text: string): boolean {
    if (text.length > MAX_STRING_BYTES - bytes) return false;
    bytes += encoder.encode(text).byteLength;
    return bytes <= MAX_STRING_BYTES;
  }

  function wellFormed(text: string): boolean {
    for (let index = 0; index < text.length; index++) {
      const code = text.charCodeAt(index);
      if (code >= 0xd800 && code <= 0xdbff) {
        const next = text.charCodeAt(++index);
        if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      } else if (code >= 0xdc00 && code <= 0xdfff) return false;
    }
    return true;
  }

  try {
    while (pending.length) {
      const entry = pending.pop();
      if (!entry) break;
      if (++count > MAX_NODES || entry.depth > MAX_DEPTH) {
        return { tag: "unsupported" };
      }
      const item = entry.value;
      if (item === null || typeof item === "boolean") {
        entry.assign(item);
      } else if (typeof item === "string") {
        if (!countString(item)) return { tag: "unsupported" };
        if (!wellFormed(item)) return { tag: "invalid" };
        entry.assign(item);
      } else if (typeof item === "number") {
        if (!Number.isSafeInteger(item)) return { tag: "unsupported" };
        entry.assign(item);
      } else if (typeof item !== "object") {
        return { tag: "invalid" };
      } else {
        if (seen.has(item)) return { tag: "unsupported" };
        seen.add(item);
        const array = Array.isArray(item);
        const prototype = Object.getPrototypeOf(item);
        if (
          array
            ? prototype !== Array.prototype
            : prototype !== Object.prototype && prototype !== null
        ) return { tag: "unsupported" };
        const keys = Reflect.ownKeys(item);
        if (
          keys.length - (array ? 1 : 0) > MAX_NODES - count - pending.length
        ) {
          return { tag: "unsupported" };
        }
        const result: unknown[] | Record<string, unknown> = array
          ? []
          : Object.create(null);
        entry.assign(result);
        if (array) {
          const length = Object.getOwnPropertyDescriptor(item, "length")?.value;
          if (
            !Number.isSafeInteger(length) || length < 0 || length > MAX_NODES
          ) {
            return { tag: "unsupported" };
          }
          if (keys.length !== length + 1) return { tag: "invalid" };
        }
        for (const key of keys) {
          if (array && key === "length") continue;
          if (typeof key !== "string" || !countString(key)) {
            return { tag: "unsupported" };
          }
          if (!wellFormed(key)) return { tag: "invalid" };
          if (
            array &&
            (!/^(0|[1-9][0-9]*)$/.test(key) || Number(key) >= keys.length - 1)
          ) return { tag: "invalid" };
          const descriptor = Object.getOwnPropertyDescriptor(item, key);
          if (!descriptor?.enumerable || !("value" in descriptor)) {
            return { tag: "invalid" };
          }
          pending.push({
            value: descriptor.value,
            depth: entry.depth + 1,
            assign: (child) =>
              Object.defineProperty(result, key, {
                value: child,
                writable: true,
                enumerable: true,
                configurable: true,
              }),
          });
        }
      }
    }
    return { tag: "copied", value: copy };
  } catch {
    return { tag: "invalid" };
  }
}
