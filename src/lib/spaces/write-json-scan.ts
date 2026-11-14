import { MAX_NUMBER_TOKEN_LENGTH } from "./write-json-integer";

export const MAX_SPACE_WRITE_JSON_BYTES = 1_000_000;
export const MAX_SPACE_WRITE_JSON_DEPTH = 64;
export const MAX_SPACE_WRITE_JSON_ITEMS = 32_768;
export const MAX_SPACE_WRITE_JSON_KEYS = 8_192;
export const MAX_SPACE_WRITE_JSON_KEY_BYTES = 8_192;
export const MAX_SPACE_WRITE_JSON_STRING_BYTES = 262_144;

const FORBIDDEN_KEYS = new Set(["", "__proto__", "prototype", "constructor"]);
type Frame = { readonly kind: "array" } | {
  readonly kind: "object";
  readonly keys: Set<string>;
};
type ParseString = (input: string) => unknown;

/** Bound structural work and reject ambiguous decoded object names before JSON.parse. */
export function scanSpaceWriteJson(text: string, parse: ParseString): void {
  const frames: Frame[] = [];
  const encoder = new TextEncoder();
  let items = 0;
  let keys = 0;
  const count = () => {
    if (++items > MAX_SPACE_WRITE_JSON_ITEMS) throw invalid();
  };
  for (let index = 0; index < text.length; index++) {
    const char = text[index];
    if (whitespace(char) || char === ":" || char === ",") continue;
    if (char === "{" || char === "[") {
      count();
      if (frames.length >= MAX_SPACE_WRITE_JSON_DEPTH) throw invalid();
      frames.push(
        char === "{" ? { kind: "object", keys: new Set() } : { kind: "array" },
      );
      continue;
    }
    if (char === "}" || char === "]") {
      const frame = frames.pop();
      if (!frame || frame.kind !== (char === "}" ? "object" : "array")) {
        throw invalid();
      }
      continue;
    }
    if (char === '"') {
      const start = index;
      let closed = false;
      while (++index < text.length) {
        if (text[index] === "\\") {
          if (++index >= text.length) throw invalid();
        } else if (text[index] === '"') {
          closed = true;
          break;
        }
      }
      if (!closed) throw invalid();
      const value = parse(text.slice(start, index + 1));
      if (typeof value !== "string" || !wellFormed(value)) throw invalid();
      let next = index + 1;
      while (next < text.length && whitespace(text[next])) next++;
      const isKey = text[next] === ":";
      const bytes = encoder.encode(value).byteLength;
      count();
      if (isKey) {
        const frame = frames.at(-1);
        if (
          !frame || frame.kind !== "object" || FORBIDDEN_KEYS.has(value) ||
          ++keys > MAX_SPACE_WRITE_JSON_KEYS ||
          bytes > MAX_SPACE_WRITE_JSON_KEY_BYTES || frame.keys.has(value)
        ) {
          throw invalid();
        }
        frame.keys.add(value);
      } else if (bytes > MAX_SPACE_WRITE_JSON_STRING_BYTES) throw invalid();
      continue;
    }
    if (char === "-" || (char >= "0" && char <= "9")) {
      const start = index;
      while (index + 1 < text.length && !delimiter(text[index + 1])) index++;
      if (index - start + 1 > MAX_NUMBER_TOKEN_LENGTH) throw invalid();
      count();
      continue;
    }
    if (char === "t" || char === "f" || char === "n") {
      const start = index;
      while (index + 1 < text.length && !delimiter(text[index + 1])) index++;
      const value = text.slice(start, index + 1);
      if (value !== "true" && value !== "false" && value !== "null") {
        throw invalid();
      }
      count();
      continue;
    }
    throw invalid();
  }
  if (frames.length) throw invalid();
}

function delimiter(value: string): boolean {
  return whitespace(value) || value === "," || value === ":" || value === "]" ||
    value === "}";
}

function whitespace(value: string): boolean {
  return value === " " || value === "\n" || value === "\r" || value === "\t";
}

function wellFormed(value: string): boolean {
  for (let index = 0; index < value.length; index++) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      if (++index >= value.length) return false;
      const low = value.charCodeAt(index);
      if (low < 0xdc00 || low > 0xdfff) return false;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) return false;
  }
  return true;
}

function invalid(): Error {
  return new Error("Invalid Space write JSON");
}
