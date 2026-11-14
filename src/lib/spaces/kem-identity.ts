import { formatDidVerificationMethod } from "@atproto/crypto-spaces";
import { isP256DidKey } from "@atproto/space";
import { isValidDid } from "@atproto/syntax-spaces";

export type SpaceKemIdentityStatus =
  | "ready"
  | "missing"
  | "invalid"
  | "mismatch";

/**
 * Compare a resolved DID document with the locally configured KEM public key.
 * The caller must independently authenticate the DID resolution and freshness.
 */
export function checkSpaceKemIdentity(
  did: string,
  publicDidKey: string,
  document: unknown,
): SpaceKemIdentityStatus {
  if (
    !isValidDid(did) || !isP256DidKey(publicDidKey) || !isObject(document) ||
    document.id !== did
  ) {
    return "invalid";
  }
  if (document.verificationMethod === undefined) return "missing";
  if (
    !Array.isArray(document.verificationMethod) ||
    !document.verificationMethod.every(isObject)
  ) return "invalid";

  const fullId = `${did}#atproto_kem`;
  const methods = document.verificationMethod.filter((method: unknown) =>
    isObject(method) && (method.id === fullId || method.id === "#atproto_kem")
  );
  if (methods.length === 0) return "missing";
  if (methods.length !== 1) return "invalid";
  const method = methods[0];
  if (
    !isObject(method) || method.controller !== did ||
    (method.type !== "Multikey" &&
      method.type !== "EcdsaSecp256r1VerificationKey2019") ||
    typeof method.publicKeyMultibase !== "string"
  ) return "invalid";
  try {
    const advertised = formatDidVerificationMethod({
      type: method.type,
      publicKeyMultibase: method.publicKeyMultibase,
    });
    if (!isP256DidKey(advertised)) return "invalid";
    return advertised === publicDidKey ? "ready" : "mismatch";
  } catch {
    return "invalid";
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
