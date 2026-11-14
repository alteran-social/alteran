import { parseExactSpaceInteger } from "./write-json-integer";
import {
  MAX_SPACE_WRITE_JSON_BYTES,
  scanSpaceWriteJson,
} from "./write-json-scan";

export type SpaceWriteJson =
  | null
  | boolean
  | string
  | number
  | bigint
  | readonly SpaceWriteJson[]
  | { readonly [key: string]: SpaceWriteJson };

export type SpaceWriteJsonResult =
  | Readonly<{ tag: "valid"; value: SpaceWriteJson }>
  | Readonly<{ tag: "invalid" | "unavailable" }>;

type SourceContext = { readonly source?: string };
type SourceReviver = (
  key: string,
  value: unknown,
  context?: SourceContext,
) => unknown;
type SourceParse = (text: string, reviver?: SourceReviver) => unknown;

/** Parse bounded Lex JSON without rounding integers or interpreting special objects. */
export function parseSpaceWriteJson(input: unknown): SpaceWriteJsonResult {
  try {
    const bytes = copyInput(input);
    if (!bytes) return failure("invalid");
    const parse = JSON.parse as unknown as SourceParse;
    if (!supportsSourceText(parse)) return failure("unavailable");
    const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true })
      .decode(bytes);
    scanSpaceWriteJson(text, (literal) => parse(literal));
    const value = parse(text, (_key, current, context) => {
      if (typeof current === "number") {
        const source = context &&
          Object.getOwnPropertyDescriptor(context, "source")?.value;
        return parseExactSpaceInteger(source);
      }
      if (Array.isArray(current)) return Object.freeze(current);
      if (current && typeof current === "object") {
        const safe: Record<string, unknown> = Object.create(null);
        for (const key of Object.keys(current)) {
          const property = Object.getOwnPropertyDescriptor(current, key);
          if (!property || !("value" in property)) {
            throw new Error("Invalid Space write JSON");
          }
          Object.defineProperty(safe, key, {
            value: property.value,
            enumerable: true,
          });
        }
        return Object.freeze(safe);
      }
      return current;
    });
    return Object.freeze({ tag: "valid", value: value as SpaceWriteJson });
  } catch {
    return failure("invalid");
  }
}

function supportsSourceText(parse: SourceParse): boolean {
  try {
    return parse(
      "9007199254740993",
      (_key, _value, context) =>
        !!context &&
        Object.getOwnPropertyDescriptor(context, "source")?.value ===
          "9007199254740993",
    ) === true;
  } catch {
    return false;
  }
}

function copyInput(input: unknown): Uint8Array | null {
  if (!ArrayBuffer.isView(input) || !(input instanceof Uint8Array)) return null;
  const prototype = Object.getPrototypeOf(Uint8Array.prototype);
  const size = Reflect.get(prototype, "byteLength", input);
  const buffer = Reflect.get(prototype, "buffer", input);
  if (
    !Number.isSafeInteger(size) || size < 1 ||
    size > MAX_SPACE_WRITE_JSON_BYTES || !(buffer instanceof ArrayBuffer)
  ) {
    return null;
  }
  const captured = new Uint8Array(size);
  Uint8Array.prototype.set.call(captured, input);
  return captured;
}

function failure(tag: "invalid" | "unavailable"): SpaceWriteJsonResult {
  return Object.freeze({ tag });
}
