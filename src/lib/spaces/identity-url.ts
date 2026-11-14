import { isValidHandle, isValidTld } from "@atproto/syntax-spaces";

/** Construct the production DID-document URL for the supported AT Protocol methods. */
export function spaceIdentityDocumentUrl(did: unknown): string | null {
  if (typeof did !== "string") return null;
  if (/^did:plc:[a-z2-7]{24}$/.test(did)) return `https://plc.directory/${did}`;
  if (!did.startsWith("did:web:")) return null;
  const hostname = did.slice("did:web:".length);
  const normalized = hostname.toLowerCase();
  if (
    hostname !== normalized || !isValidHandle(hostname) ||
    !isValidTld(normalized) ||
    normalized.endsWith(".test")
  ) return null;
  try {
    const url = new URL(`https://${normalized}/.well-known/did.json`);
    return url.hostname === normalized ? url.href : null;
  } catch {
    return null;
  }
}
