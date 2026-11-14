import {
  formatDidVerificationMethod,
  parseDidKey,
} from "@atproto/crypto-spaces";
import { isSpaceDid } from "./space-did";

/**
 * Extract the authority's signing key from an authenticated DID document.
 * DID resolution, document freshness, and transport are the caller's responsibility.
 */
export function authoritySigningKey(
  did: string,
  document: unknown,
): string | null {
  if (
    !validDocument(did, document) || !Array.isArray(document.verificationMethod)
  ) return null;
  for (const method of document.verificationMethod) {
    if (
      !isObject(method) || !matchesId(method.id, did, "atproto") ||
      method.controller !== did ||
      typeof method.type !== "string" ||
      typeof method.publicKeyMultibase !== "string"
    ) continue;
    try {
      const key = formatDidVerificationMethod({
        type: method.type,
        publicKeyMultibase: method.publicKeyMultibase,
      });
      const algorithm = parseDidKey(key).jwtAlg;
      if (algorithm === "ES256" || algorithm === "ES256K") return key;
    } catch {
      // The first valid, supported signing method is authoritative.
    }
  }
  return null;
}

/** Extract the advertised HTTPS PDS origin; this does not establish safe network routing. */
export function authorityPdsOrigin(
  did: string,
  document: unknown,
): string | null {
  if (!validDocument(did, document) || !Array.isArray(document.service)) {
    return null;
  }
  const service = document.service.find((value: unknown) =>
    isObject(value) && matchesId(value.id, did, "atproto_pds") &&
    value.type === "AtprotoPersonalDataServer"
  );
  if (!isObject(service) || typeof service.serviceEndpoint !== "string") {
    return null;
  }
  try {
    const url = new URL(service.serviceEndpoint);
    if (
      url.protocol !== "https:" || url.username || url.password ||
      url.pathname !== "/" || url.search || url.hash
    ) {
      return null;
    }
    return url.origin;
  } catch {
    return null;
  }
}

function validDocument(
  did: string,
  value: unknown,
): value is Record<string, unknown> {
  return isSpaceDid(did) && isObject(value) &&
    value.id === did;
}

function matchesId(id: unknown, did: string, fragment: string): boolean {
  return id === `#${fragment}` || id === `${did}#${fragment}`;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
