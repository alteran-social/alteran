import type { APIContext } from 'astro';
import { authErrorResponse, authenticateRequest, unauthorized } from '../../lib/auth';
import { canAccessFullAccount } from '../../lib/auth-scope';
import { resolveSecret } from '../../lib/secrets';
import { canonicalPdsOrigin, configuredHandle, validAtprotoHandle } from '../../lib/public-host';

export const prerender = false;

/**
 * com.atproto.identity.getRecommendedDidCredentials
 *
 * Returns the recommended DID credentials for the current account.
 * This includes the handle, signing key, and PDS endpoint that should be
 * used when updating the PLC identity.
 */
export async function GET({ locals, request }: APIContext) {
  const { env } = locals;

  try {
    const auth = await authenticateRequest(request, env);
    if (!auth || !canAccessFullAccount(auth.access)) return unauthorized();
  } catch (error) {
    const handled = await authErrorResponse(env, error);
    if (handled) return handled;
    throw error;
  }

  try {
    const handle = await configuredHandle(env);
    const claimedHandle = validAtprotoHandle(handle);
    const serviceEndpoint = await canonicalPdsOrigin(env);

    // Always ES256K: derive did:key from the secp256k1 signing key
    let didKey: string | undefined;
    const priv = (await resolveSecret(env.REPO_SIGNING_KEY))?.trim();
    if (!priv) {
      return new Response(
        JSON.stringify({ error: 'InvalidRequest', message: 'REPO_SIGNING_KEY not configured for ES256K' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      );
    }
    try {
      const { Secp256k1Keypair } = await import('@atproto/crypto');
      let keypair: { did: () => string };
      if (/^[0-9a-fA-F]{64}$/.test(priv)) {
        keypair = await Secp256k1Keypair.import(priv);
      } else {
        const bin = atob(priv.replace(/\s+/g, ''));
        const bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        keypair = await Secp256k1Keypair.import(bytes);
      }
      didKey = keypair.did();
    } catch (keypairError) {
      console.error('REPO_SIGNING_KEY did:key derivation failed:', keypairError);
      return new Response(
        JSON.stringify({ error: 'InvalidRequest', message: 'Failed to derive secp256k1 did:key from REPO_SIGNING_KEY' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      );
    }

    const did = await resolveSecret(env.PDS_DID);
    if (!did) {
      return new Response(JSON.stringify({ error: 'InvalidRequest', message: 'PDS_DID is not configured' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
    }
    if (!did.startsWith('did:plc:')) {
      return jsonError('UnsupportedDidMethod', 'DID credential recommendations require a did:plc account', 400);
    }

    const plcData = await readPlcData(did, request.signal);
    if (!plcData) {
      return jsonError('PlcDataUnavailable', 'Unable to verify current PLC credentials', 502);
    }
    if (Object.hasOwn(plcData.verificationMethods, 'atproto_kem')) {
      return jsonError(
        'SpacesMigrationUnsupported',
        'This account has a Spaces KEM key. Alteran cannot migrate Spaces data or recommend replacement credentials yet.',
        400,
      );
    }

    const credentials = {
      rotationKeys: plcData.rotationKeys,
      alsoKnownAs: claimedHandle ? [`at://${claimedHandle}`] : [],
      verificationMethods: { atproto: didKey },
      services: {
        atproto_pds: {
          type: 'AtprotoPersonalDataServer',
          endpoint: serviceEndpoint
        }
      }
    };

    return new Response(
      JSON.stringify(credentials),
      { status: 200, headers: { 'Content-Type': 'application/json' } }
    );
  } catch (error) {
    console.error('Get recommended credentials error:', error);
    const message = error instanceof Error ? error.message : 'Failed to get recommended credentials';
    return new Response(
      JSON.stringify({
        error: 'InternalServerError',
        message,
      }),
      { status: 500, headers: { 'Content-Type': 'application/json' } }
    );
  }
}

type PlcData = {
  readonly rotationKeys: string[];
  readonly verificationMethods: Record<string, string>;
};

async function readPlcData(did: string, signal: AbortSignal): Promise<PlcData | null> {
  try {
    const response = await fetch(`https://plc.directory/${encodeURIComponent(did)}/data`, {
      redirect: 'manual',
      signal,
    });
    if (!response.ok || response.redirected || response.type === 'opaqueredirect') {
      console.error('PLC credential lookup failed:', response.status);
      return null;
    }
    const data: unknown = await response.json();
    if (!isPlcData(data, did)) {
      console.error('PLC credential lookup returned invalid data');
      return null;
    }
    return data;
  } catch (error) {
    console.error('PLC credential lookup failed:', error);
    return null;
  }
}

function isPlcData(value: unknown, did: string): value is PlcData {
  if (!isObject(value) || value.did !== did) return false;
  if (!Array.isArray(value.rotationKeys) || value.rotationKeys.length === 0 ||
    !value.rotationKeys.every((key) => typeof key === 'string' && key.length > 0)) return false;
  if (!isObject(value.verificationMethods) ||
    !Object.values(value.verificationMethods).every((key) => typeof key === 'string')) return false;
  if (!Array.isArray(value.alsoKnownAs) ||
    !value.alsoKnownAs.every((alias) => typeof alias === 'string')) return false;
  if (!isObject(value.services) || !Object.values(value.services).every((service) =>
    isObject(service) && typeof service.type === 'string' && typeof service.endpoint === 'string'
  )) return false;
  return true;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function jsonError(error: string, message: string, status: number): Response {
  return new Response(JSON.stringify({ error, message }), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
