import type { Env } from '../env';
import { resolveSecret } from './secrets';

/**
 * Service auth verification for external services (like video.bsky.app)
 * 
 * Service auth JWTs are signed by the service's key and contain:
 * - iss: The service's DID (e.g., did:web:video.bsky.app)
 * - aud: The PDS's DID (must match our PDS_DID)
 * - lxm: The lexicon method being authorized
 * - exp/iat: Standard JWT timing claims
 */

interface ServiceAuthPayload {
  iss: string;
  aud: string;
  lxm?: string;
  exp?: number;
  iat?: number;
  jti?: string;
}

interface ServiceAuthResult {
  iss: string;
  aud: string;
  lxm?: string;
}

/**
 * Check if a Bearer token is a service auth token (has lxm claim)
 */
export function isServiceAuthToken(token: string): boolean {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return false;
    const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
    return payload.lxm != null;
  } catch {
    return false;
  }
}

/**
 * Decode JWT payload without verification (for initial inspection)
 */
function decodeJwtPayload(token: string): ServiceAuthPayload | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
    return payload;
  } catch {
    return null;
  }
}

/**
 * Resolve a DID document and extract the atproto verification key
 */
async function getVerificationKey(did: string): Promise<string | null> {
  try {
    let url: string;
    if (did.startsWith('did:web:')) {
      const host = did.slice('did:web:'.length).replace(/:/g, '/');
      url = `https://${host}/.well-known/did.json`;
    } else if (did.startsWith('did:plc:')) {
      url = `https://plc.directory/${did}`;
    } else {
      return null;
    }

    const res = await fetch(url, {
      headers: { 'Accept': 'application/json' },
    });
    if (!res.ok) return null;

    const doc = await res.json() as any;
    
    // Find atproto verification method
    const methods = doc.verificationMethod || [];
    for (const method of methods) {
      if (method.id?.endsWith('#atproto') && method.publicKeyMultibase) {
        return method.publicKeyMultibase;
      }
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Verify ES256K signature using the public key from DID document
 */
async function verifyES256KSignature(
  token: string,
  publicKeyMultibase: string
): Promise<boolean> {
  try {
    const { Secp256k1Keypair } = await import('@atproto/crypto');
    
    const parts = token.split('.');
    if (parts.length !== 3) return false;
    
    const [headerB64, payloadB64, signatureB64] = parts;
    const signingInput = `${headerB64}.${payloadB64}`;
    
    // Decode signature from base64url
    const sigB64 = signatureB64.replace(/-/g, '+').replace(/_/g, '/');
    const sigBin = atob(sigB64);
    const signature = new Uint8Array(sigBin.length);
    for (let i = 0; i < sigBin.length; i++) {
      signature[i] = sigBin.charCodeAt(i);
    }

    // The multibase key starts with 'z' for base58btc encoding
    // Format: z + multicodec prefix (0xe7 0x01 for secp256k1) + compressed public key
    if (!publicKeyMultibase.startsWith('z')) {
      return false;
    }

    // Use @atproto/crypto to verify
    const { verifySignature } = await import('@atproto/crypto');
    const data = new TextEncoder().encode(signingInput);
    
    // Convert multibase to did:key format for verification
    const didKey = `did:key:${publicKeyMultibase}`;
    const isValid = await verifySignature(didKey, data, signature);
    
    return isValid;
  } catch (e) {
    console.error('Service auth signature verification failed:', e);
    return false;
  }
}

/**
 * Verify a service auth request
 * 
 * @param env - Environment with PDS_DID
 * @param request - The incoming request
 * @returns The verified service auth payload, or null if not service auth / invalid
 */
export async function verifyServiceAuth(
  env: Env,
  request: Request
): Promise<ServiceAuthResult | null> {
  const auth = request.headers.get('authorization');
  if (!auth?.startsWith('Bearer ')) return null;

  const token = auth.slice(7).trim();
  if (!isServiceAuthToken(token)) return null;

  const payload = decodeJwtPayload(token);
  if (!payload || !payload.iss || !payload.aud) return null;

  // Check audience matches our PDS DID (accept both did:plc and did:web forms)
  const pdsDid = await resolveSecret(env.PDS_DID);
  const hostname = env.PDS_HOSTNAME || env.PDS_HANDLE;
  const didWebAlt = hostname ? `did:web:${hostname}` : null;
  const validAudiences = [pdsDid, didWebAlt].filter(Boolean) as string[];
  
  if (!validAudiences.includes(payload.aud)) return null;

  // Check expiration
  if (payload.exp) {
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp < now) return null;
  }

  // Get the issuer's verification key from their DID document
  const publicKey = await getVerificationKey(payload.iss);
  if (!publicKey) return null;

  // Verify the signature
  const isValid = await verifyES256KSignature(token, publicKey);
  if (!isValid) return null;

  return {
    iss: payload.iss,
    aud: payload.aud,
    lxm: payload.lxm,
  };
}
