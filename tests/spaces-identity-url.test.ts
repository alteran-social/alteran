import { describe, it } from "./helpers/bdd";
import { expect } from "@std/expect";
import { spaceIdentityDocumentUrl } from "../src/lib/spaces/identity-url";

describe("Spaces identity document URLs", () => {
  it("uses the fixed PLC directory for canonical did:plc identifiers", () => {
    const did = "did:plc:ztamizklsl7koph5mbiuuuc4";
    expect(spaceIdentityDocumentUrl(did)).toBe(`https://plc.directory/${did}`);
    for (
      const invalid of [
        "did:plc:alice",
        "did:plc:Ztamizklsl7koph5mbiuuuc4",
        "did:plc:ztamizklsl7koph5mbiuuuc0",
      ]
    ) {
      expect(spaceIdentityDocumentUrl(invalid)).toBeNull();
    }
  });

  it("uses the hostname-level did:web location for valid DNS names", () => {
    expect(spaceIdentityDocumentUrl("did:web:publisher.example.com")).toBe(
      "https://publisher.example.com/.well-known/did.json",
    );
    expect(spaceIdentityDocumentUrl("did:web:xn--bcher-kva.de")).toBe(
      "https://xn--bcher-kva.de/.well-known/did.json",
    );
  });

  it("rejects paths, ports, IP literals, userinfo and reserved domains", () => {
    for (
      const invalid of [
        "did:web:publisher.example.com:user",
        "did:web:Publisher.Example.com",
        "did:web:xn--abc.com",
        "did:web:publisher.example.com%3A8443",
        "did:web:localhost",
        "did:web:127.0.0.1",
        "did:web:example.com@localhost",
        "did:web:internal.local",
        "did:web:issuer.example",
        "did:web:issuer.test",
        "did:web:foo.onion",
        "did:web:publisher.example.com/other",
        "did:example:alice",
        null,
      ]
    ) expect(spaceIdentityDocumentUrl(invalid)).toBeNull();
  });
});
