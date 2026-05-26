import { describe, it } from "./helpers/bdd";
import { expect } from "@std/expect";
import { parseRepositoryRecord } from "../src/lib/repo-write-data";
import { recordToIpld } from "../src/services/repo/blockstore-ops";

const BLOB_CID = "bafkreigh2akiscaildc4q7fapfs3krvmxz2s5tapqyqdr6fhyjn4zpd6du";

describe("repo write record parser", () => {
  it("requires an explicit matching string type", () => {
    expect(() =>
      parseRepositoryRecord("app.bsky.feed.post", {
        text: "missing",
      })
    ).toThrow("record $type is required");

    expect(() =>
      parseRepositoryRecord("app.bsky.feed.post", {
        $type: 123,
        text: "wrong",
      })
    ).toThrow("record $type must be a string");

    expect(() =>
      parseRepositoryRecord("app.bsky.feed.post", {
        $type: "app.bsky.actor.profile",
        text: "wrong",
      })
    ).toThrow("record $type must match collection");
  });

  it("returns a deeply frozen clone without mutating caller input", () => {
    const input = {
      $type: "com.example.record",
      nested: {
        tags: ["one"],
      },
    };

    const parsed = parseRepositoryRecord("com.example.record", input);

    expect(parsed).not.toBe(input);
    expect(parsed.nested).not.toBe(input.nested);
    expect(Object.isFrozen(parsed)).toBe(true);
    expect(Object.isFrozen(parsed.nested)).toBe(true);
    const parsedNested = parsed.nested as { readonly tags: readonly string[] };
    expect(Object.isFrozen(parsedNested.tags)).toBe(true);

    input.nested.tags.push("two");
    expect(parsedNested.tags).toEqual(["one"]);
  });

  it("rejects empty nested type discriminators", () => {
    expect(() =>
      parseRepositoryRecord("com.example.record", {
        $type: "com.example.record",
        embed: { $type: "" },
      })
    ).toThrow("record/embed $type must be a non-empty string");
  });

  it("rejects malformed blob fields before lexicon validation", () => {
    const validBlob = {
      $type: "blob",
      ref: { $link: BLOB_CID },
      mimeType: "image/png",
      size: 0,
    };

    expect(() =>
      parseRepositoryRecord("com.example.record", {
        $type: "com.example.record",
        blob: { ...validBlob, mimeType: "not-a-mime" },
      })
    ).toThrow("mimeType must be a valid MIME type");

    expect(() =>
      parseRepositoryRecord("com.example.record", {
        $type: "com.example.record",
        blob: { ...validBlob, size: -1 },
      })
    ).toThrow("size must be a non-negative safe integer");

    expect(() =>
      parseRepositoryRecord("com.example.record", {
        $type: "com.example.record",
        blob: { ...validBlob, size: Number.MAX_SAFE_INTEGER + 1 },
      })
    ).toThrow("size must be a non-negative safe integer");
  });

  it("accepts URL-safe base64 bytes through IPLD conversion", () => {
    const parsed = parseRepositoryRecord("com.example.record", {
      $type: "com.example.record",
      bytes: { $bytes: "YWJj-_0" },
      blob: {
        $type: "blob",
        ref: { $link: BLOB_CID },
        mimeType: "image/png",
        size: 0,
      },
    });
    const ipld = recordToIpld(parsed) as {
      readonly bytes: Uint8Array;
      readonly blob: { readonly size: number };
    };

    expect(Array.from(ipld.bytes)).toEqual([97, 98, 99, 251, 253]);
    expect(ipld.blob.size).toBe(0);
  });

  it("accepts atproto lex-json permissive trailing bytes padding", () => {
    const parsed = parseRepositoryRecord("com.example.record", {
      $type: "com.example.record",
      twoBytes: { $bytes: "YWI==" },
      threeBytes: { $bytes: "YWJj=" },
      emptyBytes: { $bytes: "====" },
    });
    const ipld = recordToIpld(parsed) as {
      readonly twoBytes: Uint8Array;
      readonly threeBytes: Uint8Array;
      readonly emptyBytes: Uint8Array;
    };

    expect(Array.from(ipld.twoBytes)).toEqual([97, 98]);
    expect(Array.from(ipld.threeBytes)).toEqual([97, 98, 99]);
    expect(Array.from(ipld.emptyBytes)).toEqual([]);
  });

  it("rejects bytes values that would truncate trailing sextets", () => {
    expect(() =>
      parseRepositoryRecord("com.example.record", {
        $type: "com.example.record",
        bytes: { $bytes: "Y" },
      })
    ).toThrow("record/bytes must contain RFC-4648 base64 bytes");
  });
});
