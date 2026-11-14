import { parseDidKey } from '@atproto/crypto-spaces';
import {
  CLOCK_SKEW_SEC,
  parseSpaceToken,
  type SpaceToken,
  SpaceTokenError,
  verifyCredentialSig,
  verifySpaceToken,
} from '@atproto/space';
import { isValidDid, SpaceRef } from '@atproto/syntax-spaces';

export type SpaceCredentialVerification =
  | {
    readonly tag: 'authorized';
    readonly space: string;
    readonly authority: string;
    readonly audience: string;
    readonly credentialId: string;
    readonly expiresAt: number;
  }
  | { readonly tag: 'invalid' }
  | { readonly tag: 'unavailable' };

export type VerifySpaceCredentialOptions = {
  readonly space: string;
  /** Derived by the caller from the locally served repo or space authority. */
  readonly expectedAudience: string;
  readonly headers: Headers;
  /** Resolve only the authority's authenticated #atproto verification method. */
  readonly getAuthoritySigningKey: (
    authority: string,
    forceRefresh: boolean,
  ) => Promise<string>;
  /** Check locally received and authenticated revocations for this space. */
  readonly isRevoked: (space: string, credentialId: string) => Promise<boolean>;
};

const MAX_HEADER_LENGTH = 8192;
const MAX_SPACE_LENGTH = 8192;

/** Verify a read credential. The caller must select the locally served resource. */
export async function verifySpaceCredential(
  options: VerifySpaceCredentialOptions,
): Promise<SpaceCredentialVerification> {
  const {
    space,
    expectedAudience,
    headers,
    getAuthoritySigningKey,
    isRevoked,
  } = options;
  if (
    typeof space !== 'string' || space.length > MAX_SPACE_LENGTH ||
    typeof expectedAudience !== 'string' || !isValidDid(expectedAudience) ||
    !headers || typeof headers.get !== 'function'
  ) return { tag: 'invalid' };

  let authority: string;
  try {
    authority = SpaceRef.parse(space).spaceDid;
  } catch {
    return { tag: 'invalid' };
  }

  const authorization = headers.get('authorization');
  const audience = headers.get('atproto-space-audience');
  const signatureInput = headers.get('signature-input');
  const signature = headers.get('signature');
  if (
    !authorization || !audience || !signatureInput || !signature ||
    [authorization, audience, signatureInput, signature].some((value) =>
      value.length > MAX_HEADER_LENGTH
    ) ||
    audience !== expectedAudience
  ) return { tag: 'invalid' };

  const match =
    /^atproto-space-credential[ \t]+([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/i
      .exec(authorization);
  if (!match) return { tag: 'invalid' };
  const credential = match[1];

  let notBefore: number | undefined;
  try {
    const parsed = parseSpaceToken('credential', credential);
    if (
      parsed.payload.iss !== authority || parsed.payload.sub !== space ||
      'aud' in parsed.payload || 'crit' in parsed.header ||
      'b64' in parsed.header
    ) {
      return { tag: 'invalid' };
    }
    if ('nbf' in parsed.payload) {
      const value = parsed.payload.nbf;
      if (typeof value !== 'number' || !Number.isFinite(value)) {
        return { tag: 'invalid' };
      }
      notBefore = value;
      if (notBefore > Math.floor(Date.now() / 1000) + CLOCK_SKEW_SEC) {
        return { tag: 'invalid' };
      }
    }
    await verifyCredentialSig({
      authorization,
      'atproto-space-audience': audience,
      'signature-input': signatureInput,
      signature,
    }, parsed.payload.cnf.kid);
  } catch {
    return { tag: 'invalid' };
  }

  let resolvedKey = false;
  let resolverUnavailable = false;
  let refreshOnly = false;
  let refreshedKey: Promise<string> | undefined;

  const resolveKey = async (
    issuer: string,
    forceRefresh: boolean,
  ): Promise<string> => {
    if (issuer !== authority) throw new Error('Unexpected space authority');
    const refresh = refreshOnly || forceRefresh;
    const load = async (): Promise<string> => {
      try {
        const key = await getAuthoritySigningKey(authority, refresh);
        const algorithm = parseDidKey(key).jwtAlg;
        if (algorithm !== 'ES256' && algorithm !== 'ES256K') {
          throw new Error('Invalid signing key');
        }
        resolvedKey = true;
        return key;
      } catch {
        resolverUnavailable = true;
        throw new Error('Space authority key unavailable');
      }
    };
    if (!refresh) return load();
    refreshedKey ??= load();
    return refreshedKey;
  };

  const verify = () =>
    verifySpaceToken('credential', credential, {
      sub: space,
      getSigningKey: resolveKey,
    });

  let verified: SpaceToken<'credential'>;
  try {
    verified = await verify();
  } catch (error) {
    if (resolverUnavailable) return { tag: 'unavailable' };
    if (
      !(error instanceof SpaceTokenError) || error.code !== 'BadJwtSignature' ||
      !resolvedKey || refreshedKey
    ) return { tag: 'invalid' };

    // The SDK does not refresh a cached key when the signing algorithm changed.
    refreshOnly = true;
    try {
      verified = await verify();
    } catch {
      return { tag: resolverUnavailable ? 'unavailable' : 'invalid' };
    }
  }

  try {
    const revoked = await isRevoked(space, verified.payload.jti);
    if (revoked !== false) {
      return { tag: revoked === true ? 'invalid' : 'unavailable' };
    }
  } catch {
    return { tag: 'unavailable' };
  }

  const now = Math.floor(Date.now() / 1000);
  if (
    now - CLOCK_SKEW_SEC >= verified.payload.exp ||
    verified.payload.iat > now + CLOCK_SKEW_SEC ||
    (notBefore !== undefined && notBefore > now + CLOCK_SKEW_SEC)
  ) {
    return { tag: 'invalid' };
  }

  return {
    tag: 'authorized',
    space,
    authority,
    audience,
    credentialId: verified.payload.jti,
    expiresAt: verified.payload.exp,
  };
}
