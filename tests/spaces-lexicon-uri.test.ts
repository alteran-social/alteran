import { describe, it } from "./helpers/bdd";
import { expect } from "@std/expect";
import { isLexiconUri } from "../src/lib/spaces/lexicon-uri";

describe("Lexicon URI validation", () => {
  it("accepts generic absolute RFC 3986 URI forms", () => {
    for (
      const value of [
        "https://example.com/a%20b?x=1&y=2#fragment",
        "com.example+app://example.com/path",
        "did:plc:abcdefghijklmnopqrstuvwx",
        "urn:example:animal:ferret:nose",
        "mailto:user@example.com",
        "file:///example",
        "foo:",
        "https://[2001:db8::1]:8443/a",
        "example://[v1.some:future]/path",
        "example://user:password@example.com:/path",
      ]
    ) expect(isLexiconUri(value)).toBe(true);
  });

  it("rejects bad escapes, malformed authorities and non-URI characters", () => {
    for (
      const value of [
        "https://example.com/%ZZ",
        "https://example.com/%",
        "https://example.com/a b",
        "https://example.com/é",
        "https://[::1/path",
        "https://[not-an-ip]/path",
        "https://example.com:port/path",
        "https://one@two@example.com/path",
        "https://example.com/path#one#two",
        "1scheme:value",
        "relative/path",
        `https://example.com/${"a".repeat(8193)}`,
      ]
    ) expect(isLexiconUri(value)).toBe(false);
  });
});
