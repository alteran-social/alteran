import { expect } from "@std/expect";
import { describe, it } from "@std/testing/bdd";
import { validateSpaceLexiconSemantics } from "../src/lib/spaces/lexicon-semantics";

function document(definitions: Record<string, unknown> = {}) {
  return {
    $type: "com.atproto.lexicon.schema",
    lexicon: 1,
    id: "com.example.forum",
    defs: {
      main: { type: "space", key: "any", collections: ["com.example.post"] },
      ...definitions,
    },
  };
}

function result(definitions: Record<string, unknown>) {
  return validateSpaceLexiconSemantics(document(definitions)).tag;
}

describe("Space Lexicon semantics", () => {
  it("accepts the pinned alpha Space declaration and ordinary extension fields", () => {
    expect(
      validateSpaceLexiconSemantics({
        ...document(),
        extension: { type: "union", refs: [], closed: true },
        defs: {
          main: {
            type: "space",
            key: "literal:self",
            collections: [],
            title: "Forum",
            "title:lang": { en: "Forum" },
            extension: { type: "integer", minimum: 5, maximum: -5 },
          },
        },
      }).tag,
    ).toBe("valid");
  });

  it("rejects malformed Space declarations", () => {
    for (
      const main of [
        { type: "space", key: "bad key", collections: [] },
        { type: "space", key: "any", collections: ["*"] },
        { type: "space", key: "any" },
        { type: "string" },
      ]
    ) {
      expect(
        validateSpaceLexiconSemantics({ ...document(), defs: { main } }).tag,
      )
        .toBe("invalid");
    }
  });

  it("accepts modern formats and valid recursive local references", () => {
    expect(result({
      first: {
        type: "object",
        required: ["second"],
        properties: {
          second: { type: "ref", ref: "#second" },
          variants: {
            type: "union",
            refs: ["com.example.forum#second"],
            closed: true,
          },
          owner: { type: "string", format: "did" },
          space: { type: "string", format: "space-ref" },
        },
      },
      second: {
        type: "object",
        properties: { next: { type: "ref", ref: "#first" } },
      },
      children: { type: "array", items: { type: "ref", ref: "#children" } },
    })).toBe("valid");
  });

  it("rejects dangling, malformed and disallowed local references", () => {
    for (
      const reference of ["#missing", "#", "##a", "not-an-nsid#x", "#main"]
    ) {
      expect(
        result({
          a: { type: "array", items: { type: "ref", ref: reference } },
        }),
      )
        .toBe("invalid");
    }
    expect(result({
      symbol: { type: "token" },
      a: { type: "array", items: { type: "ref", ref: "#symbol" } },
    })).toBe("invalid");
    expect(result({
      text: { type: "string" },
      a: { type: "array", items: { type: "union", refs: ["#text"] } },
    })).toBe("invalid");
  });

  it("reports unresolved external references without treating them as proof", () => {
    for (
      const reference of ["com.example.external", "com.example.external#item"]
    ) {
      expect(
        result({
          a: { type: "array", items: { type: "ref", ref: reference } },
        }),
      )
        .toBe("unsupported");
      expect(
        result({
          a: { type: "array", items: { type: "union", refs: [reference] } },
        }),
      )
        .toBe("unsupported");
    }
  });

  it("allows empty open unions but rejects empty closed unions", () => {
    const schema = (closed: boolean) => ({
      a: { type: "array", items: { type: "union", refs: [], closed } },
    });
    expect(result(schema(false))).toBe("valid");
    expect(result(schema(true))).toBe("invalid");
  });

  it("validates numeric constraints and defaults against the allowed set", () => {
    expect(
      result({ a: { type: "integer", minimum: -10, maximum: 3, default: 0 } }),
    )
      .toBe("valid");
    for (
      const value of [
        { type: "integer", minimum: 4, maximum: 3 },
        { type: "integer", minimum: 2, default: 1 },
        { type: "integer", maximum: 2, enum: [1, 3] },
        { type: "integer", const: 1, enum: [2, 3] },
        { type: "integer", default: 1, enum: [2, 3] },
        { type: "boolean", const: true, default: false },
        { type: "string", const: "a", default: "a" },
      ]
    ) expect(result({ a: value })).toBe("invalid");
    expect(result({ a: { type: "boolean", const: true, default: true } })).toBe(
      "valid",
    );
  });

  it("uses UTF-8 byte lengths and grapheme counts for literal values", () => {
    expect(
      result({ a: { type: "string", const: "é", minLength: 2, maxLength: 2 } }),
    )
      .toBe("valid");
    expect(result({ a: { type: "string", const: "é", maxLength: 1 } })).toBe(
      "invalid",
    );
    expect(result({ a: { type: "string", const: "🇬🇧", maxGraphemes: 1 } }))
      .toBe("valid");
    expect(result({ a: { type: "string", const: "ab", maxGraphemes: 1 } }))
      .toBe("invalid");
    expect(result({ a: { type: "string", minGraphemes: 3, maxGraphemes: 2 } }))
      .toBe("invalid");
  });

  it("rejects inconsistent size ranges and invalid blob media ranges", () => {
    for (
      const value of [
        { type: "string", maxLength: -1 },
        { type: "bytes", minLength: -1 },
        { type: "bytes", minLength: 4, maxLength: 3 },
        {
          type: "array",
          minLength: 1,
          maxLength: 0,
          items: { type: "string" },
        },
        { type: "blob", maxSize: -1 },
        { type: "blob", accept: ["text/ht*"] },
      ]
    ) expect(result({ a: value })).toBe("invalid");
    expect(
      result({ a: { type: "blob", accept: ["image/*", "*/*", "text/plain"] } }),
    )
      .toBe("valid");
  });

  it("checks required and nullable fields against own property names", () => {
    expect(
      result({ a: { type: "object", required: ["missing"], properties: {} } }),
    )
      .toBe("invalid");
    expect(
      result({ a: { type: "object", nullable: ["missing"], properties: {} } }),
    )
      .toBe("invalid");
    expect(
      result({ a: { type: "object", required: ["toString"], properties: {} } }),
    )
      .toBe("invalid");
  });

  it("checks only positions where schema types are allowed", () => {
    for (
      const value of [
        { type: "ref", ref: "#missing" },
        { type: "unknown" },
        { type: "space", key: "any", collections: [] },
        { type: "array", items: { type: "object", properties: {} } },
        {
          type: "object",
          properties: { nested: { type: "object", properties: {} } },
        },
      ]
    ) expect(result({ a: value })).toBe("invalid");
  });

  it("does not claim support for unverified formats and future schema types", () => {
    expect(
      result({
        a: { type: "string", format: "did", default: "did:example:alice" },
      }),
    )
      .toBe("unsupported");
    expect(result({ a: { type: "string", format: "future-format" } })).toBe(
      "unsupported",
    );
    expect(result({ a: { type: "future-type" } })).toBe("unsupported");
    expect(validateSpaceLexiconSemantics({ ...document(), lexicon: 2 }).tag)
      .toBe("unsupported");
  });

  it("does not execute getters or accept cyclic object graphs", () => {
    let invoked = false;
    const value = document();
    Object.defineProperty(value, "extension", {
      enumerable: true,
      get() {
        invoked = true;
        return "value";
      },
    });
    expect(validateSpaceLexiconSemantics(value).tag).toBe("invalid");
    expect(invoked).toBe(false);
    const cyclic: Record<string, unknown> = document();
    cyclic.extension = cyclic;
    expect(validateSpaceLexiconSemantics(cyclic).tag).toBe("unsupported");
    expect(
      validateSpaceLexiconSemantics({ ...document(), extension: "\ud800" }).tag,
    )
      .toBe("invalid");
  });

  it("does not validate malformed or unsupported data-model compounds", () => {
    for (
      const extension of [
        { $bytes: false },
        { $link: false },
        { $bytes: "YQ==", extra: true },
        { $type: 42 },
      ]
    ) {
      expect(validateSpaceLexiconSemantics({ ...document(), extension }).tag)
        .toBe("invalid");
    }
    for (
      const extension of [
        { $bytes: "YQ==" },
        { $link: "not-a-cid" },
        { $type: "blob", ref: null },
        { $future: "value" },
        { $type: "not-an-nsid" },
      ]
    ) {
      expect(validateSpaceLexiconSemantics({ ...document(), extension }).tag)
        .toBe("unsupported");
    }
    expect(
      validateSpaceLexiconSemantics({
        ...document(),
        $type: "com.example.wrong",
      }).tag,
    ).toBe("invalid");
    expect(
      validateSpaceLexiconSemantics({
        ...document(),
        extension: { $type: "com.example.defs#view", title: "ordinary" },
      }).tag,
    ).toBe("valid");
  });

  it("enforces bounded depth, item count and string bytes", () => {
    const deep: Record<string, unknown> = {};
    let current = deep;
    for (let index = 0; index < 70; index++) {
      const next = {};
      current.next = next;
      current = next;
    }
    expect(validateSpaceLexiconSemantics({ ...document(), deep }).tag).toBe(
      "unsupported",
    );
    expect(
      validateSpaceLexiconSemantics({
        ...document(),
        extension: Array.from({ length: 50_001 }, () => 1),
      }).tag,
    ).toBe("unsupported");
    expect(
      validateSpaceLexiconSemantics({
        ...document(),
        extension: "x".repeat(1024 * 1024),
      }).tag,
    )
      .toBe("unsupported");
    expect(
      result({
        a: { type: "string", const: "a".repeat(32_769), maxGraphemes: 32_769 },
      }),
    )
      .toBe("unsupported");
  });
});
