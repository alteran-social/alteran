import { expect } from "@std/expect";
import { describe, it } from "./helpers/bdd";
import {
  parseSpaceWriteJson,
  type SpaceWriteJson,
} from "../src/lib/spaces/write-json";
import {
  MAX_SPACE_WRITE_JSON_BYTES,
  MAX_SPACE_WRITE_JSON_DEPTH,
  MAX_SPACE_WRITE_JSON_ITEMS,
  MAX_SPACE_WRITE_JSON_KEY_BYTES,
  MAX_SPACE_WRITE_JSON_KEYS,
  MAX_SPACE_WRITE_JSON_STRING_BYTES,
} from "../src/lib/spaces/write-json-scan";
import { MAX_NUMBER_TOKEN_LENGTH } from "../src/lib/spaces/write-json-integer";

const encoder = new TextEncoder();
const parse = (text: string) => parseSpaceWriteJson(encoder.encode(text));
function parsed(text: string): SpaceWriteJson {
  const result = parse(text);
  if (result.tag !== "valid") throw new Error("Expected valid JSON");
  return result.value;
}

describe("bounded Space write JSON parsing", () => {
  it("preserves exact signed-64-bit integers and exact decimal spellings", () => {
    for (
      const [text, expected] of [
        ["0", 0],
        ["-0", 0],
        ["1.000", 1],
        ["1e3", 1000],
        ["4.2e+1", 42],
        ["-100e-2", -1],
        ["0.000001e6", 1],
        ["0.000e-128", 0],
        ["9007199254740991.000", 9007199254740991],
        ["9007199254740992", 9007199254740992n],
        ["-9007199254740992", -9007199254740992n],
        ["9223372036854775807", 9223372036854775807n],
        ["-9223372036854775808", -9223372036854775808n],
        ["9.223372036854775807e18", 9223372036854775807n],
        ["-9.223372036854775808e18", -9223372036854775808n],
        ["92233720368547758070e-1", 9223372036854775807n],
      ] as const
    ) expect(parsed(text)).toEqual(expected);
  });

  it("rejects fractional, rounded, overflowing and excessive numeric tokens", () => {
    for (
      const text of [
        "1.00000000000000001",
        "0.99999999999999999",
        "9007199254740991.1",
        "-9223372036854775808.1",
        "2.5",
        "1e-1",
        "9223372036854775808",
        "-9223372036854775809",
        "1e129",
        "0e129",
        "1e-129",
        "1e999999999999999999",
        "NaN",
        "Infinity",
        "+1",
        "01",
        "0x1",
        "1.",
        "1e",
        `0.${"0".repeat(MAX_NUMBER_TOKEN_LENGTH - 1)}`,
      ]
    ) expect(parse(text).tag).toBe("invalid");
    expect(parsed(`0.${"0".repeat(MAX_NUMBER_TOKEN_LENGTH - 2)}`)).toBe(0);
  });

  it("matches exact arithmetic for varied decimal and exponent forms", () => {
    for (let value = -250; value <= 250; value++) {
      expect(parsed(`${value}.000e0`)).toBe(value);
      expect(parsed(`${value * 100}e-2`)).toBe(value);
      expect(parsed(`${value}e+2`)).toBe(value * 100);
      if (value !== 0) expect(parse(`${value}.001`).tag).toBe("invalid");
    }
  });

  it("agrees with an independent rational arithmetic oracle", () => {
    let state = 123456789;
    const next = () => {
      state = (state * 48271) % 2147483647;
      return state;
    };
    for (let index = 0; index < 2_000; index++) {
      const integer = String(next() % 1_000_000);
      const fractionalLength = next() % 8;
      const fraction = String(next() % 100_000_000).padStart(8, "0").slice(
        0,
        fractionalLength,
      );
      const exponent = next() % 21 - 10;
      const negative = next() % 2 === 0;
      const literal = `${negative ? "-" : ""}${integer}${
        fraction ? `.${fraction}` : ""
      }e${exponent}`;
      let numerator = BigInt(integer + fraction) * (negative ? -1n : 1n);
      let denominator = 10n ** BigInt(fraction.length);
      if (exponent >= 0) numerator *= 10n ** BigInt(exponent);
      else denominator *= 10n ** BigInt(-exponent);
      const value = numerator / denominator;
      const valid = numerator % denominator === 0n && value >= -(1n << 63n) &&
        value <= (1n << 63n) - 1n;
      const result = parse(literal);
      if (!valid) expect(result.tag).toBe("invalid");
      else {
        if (
          result.tag !== "valid" ||
          (typeof result.value !== "number" && typeof result.value !== "bigint")
        ) {
          throw new Error("Expected an exact integer");
        }
        expect(BigInt(result.value)).toBe(value);
      }
    }
  });

  it("rejects decoded duplicate and prototype-sensitive keys but preserves wrapper objects", () => {
    for (
      const text of [
        '{"a":1,"a":2}',
        '{"a":1,"\\u0061":2}',
        '{"\\ud83d\\udca1":1,"💡":2}',
        '{"__proto__":1}',
        '{"\\u005f_proto__":1}',
        '{"constructor":1}',
        '{"prototype":1}',
        '{"":1}',
      ]
    ) expect(parse(text).tag).toBe("invalid");
    const result = parsed(
      '{"record":{"link":{"$link":"bafyexample"},"bytes":{"$bytes":"AQID"}}}',
    );
    if (!result || typeof result !== "object" || Array.isArray(result)) {
      throw new Error("Expected object");
    }
    const outer = result as {
      readonly record: { readonly link: unknown; readonly bytes: unknown };
    };
    expect(outer.record.link).toEqual(
      Object.assign(Object.create(null), { $link: "bafyexample" }),
    );
    expect(outer.record.bytes).toEqual(
      Object.assign(Object.create(null), { $bytes: "AQID" }),
    );
  });

  it("rejects malformed UTF-8, BOMs, unpaired surrogates and invalid JSON", () => {
    for (
      const bytes of [
        new Uint8Array([0x22, 0xc0, 0xaf, 0x22]),
        new Uint8Array([0x22, 0xed, 0xa0, 0x80, 0x22]),
        new Uint8Array([0xef, 0xbb, 0xbf, 0x7b, 0x7d]),
      ]
    ) expect(parseSpaceWriteJson(bytes).tag).toBe("invalid");
    for (
      const text of [
        '"\\ud800"',
        '"\\udc00"',
        '{"\\ud800":1}',
        "[1,]",
        '{"a":1} trailing',
        "",
      ]
    ) {
      expect(parse(text).tag).toBe("invalid");
    }
    expect(parsed('"\\ud83d\\udca1"')).toBe("💡");
    expect(parsed('"�"')).toBe("�");
  });

  it("enforces byte, depth, item, key and string limits at their boundaries", () => {
    const small = '{"v":true}';
    expect(
      parse(small + " ".repeat(MAX_SPACE_WRITE_JSON_BYTES - small.length)).tag,
    ).toBe("valid");
    expect(
      parse(small + " ".repeat(MAX_SPACE_WRITE_JSON_BYTES - small.length + 1))
        .tag,
    ).toBe("invalid");
    expect(
      parse(
        "[".repeat(MAX_SPACE_WRITE_JSON_DEPTH) + "0" +
          "]".repeat(MAX_SPACE_WRITE_JSON_DEPTH),
      ).tag,
    ).toBe("valid");
    expect(
      parse(
        "[".repeat(MAX_SPACE_WRITE_JSON_DEPTH + 1) + "0" +
          "]".repeat(MAX_SPACE_WRITE_JSON_DEPTH + 1),
      ).tag,
    ).toBe("invalid");
    expect(
      parse(`[${Array(MAX_SPACE_WRITE_JSON_ITEMS - 1).fill("0").join(",")}]`)
        .tag,
    ).toBe("valid");
    expect(
      parse(`[${Array(MAX_SPACE_WRITE_JSON_ITEMS).fill("0").join(",")}]`).tag,
    ).toBe("invalid");
    const fields = Array.from(
      { length: MAX_SPACE_WRITE_JSON_KEYS },
      (_, index) => `"k${index}":0`,
    );
    expect(parse(`{${fields.join(",")}}`).tag).toBe("valid");
    expect(parse(`{${fields.join(",")},"extra":0}`).tag).toBe("invalid");
    expect(parse(`{"${"k".repeat(MAX_SPACE_WRITE_JSON_KEY_BYTES)}":0}`).tag)
      .toBe("valid");
    expect(parse(`{"${"k".repeat(MAX_SPACE_WRITE_JSON_KEY_BYTES + 1)}":0}`).tag)
      .toBe("invalid");
    expect(parse(`"${"a".repeat(MAX_SPACE_WRITE_JSON_STRING_BYTES)}"`).tag)
      .toBe("valid");
    expect(parse(`"${"a".repeat(MAX_SPACE_WRITE_JSON_STRING_BYTES + 1)}"`).tag)
      .toBe("invalid");
    expect(parse(`"${"💡".repeat(MAX_SPACE_WRITE_JSON_STRING_BYTES / 4)}"`).tag)
      .toBe("valid");
    expect(
      parse(`"${"💡".repeat(MAX_SPACE_WRITE_JSON_STRING_BYTES / 4 + 1)}"`).tag,
    ).toBe("invalid");
  });

  it("copies input and returns deeply frozen independent values", () => {
    const bytes = encoder.encode('{"outer":[{"n":9007199254740993}]}');
    const original = bytes.slice();
    const result = parseSpaceWriteJson(bytes);
    expect(bytes).toEqual(original);
    const surrounding = new Uint8Array(bytes.length + 2);
    surrounding.set(bytes, 1);
    expect(parseSpaceWriteJson(surrounding.subarray(1, -1)).tag).toBe("valid");
    if (
      result.tag !== "valid" || !result.value ||
      typeof result.value !== "object" || Array.isArray(result.value)
    ) {
      throw new Error("Expected object");
    }
    const object = result.value as {
      readonly outer: readonly { readonly n: bigint }[];
    };
    bytes.fill(0);
    expect(object.outer[0].n).toBe(9007199254740993n);
    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(object)).toBe(true);
    expect(Object.isFrozen(object.outer)).toBe(true);
    expect(Object.isFrozen(object.outer[0])).toBe(true);
    expect(Object.getPrototypeOf(object)).toBe(null);
    let rejected = false;
    try {
      Object.defineProperty(object.outer[0], "n", { value: 0 });
    } catch {
      rejected = true;
    }
    expect(rejected).toBe(true);
    if (typeof SharedArrayBuffer !== "undefined") {
      expect(parseSpaceWriteJson(new Uint8Array(new SharedArrayBuffer(2))).tag)
        .toBe("invalid");
    }
  });

  it("fails closed when JSON source-token context is unavailable", () => {
    const descriptor = Object.getOwnPropertyDescriptor(JSON, "parse");
    if (!descriptor) throw new Error("Missing JSON.parse descriptor");
    const original = JSON.parse;
    try {
      Object.defineProperty(JSON, "parse", {
        ...descriptor,
        value: (
          text: string,
          reviver?: (key: string, value: unknown) => unknown,
        ) =>
          original(
            text,
            reviver ? (key, value) => reviver(key, value) : undefined,
          ),
      });
      expect(parse('{"value":1}')).toEqual({ tag: "unavailable" });
    } finally {
      Object.defineProperty(JSON, "parse", descriptor);
    }
  });

  it("returns only fixed generic failures", () => {
    const secretMarker = "private-space-synthetic-marker";
    for (
      const input of [
        null,
        1,
        {},
        secretMarker,
        new Uint8Array(),
        encoder.encode(`{"${secretMarker}":1,"${secretMarker}":2}`),
      ]
    ) {
      const result = parseSpaceWriteJson(input);
      expect(result).toEqual({ tag: "invalid" });
      expect(JSON.stringify(result).includes(secretMarker)).toBe(false);
      expect(Object.isFrozen(result)).toBe(true);
    }
  });
});
