import type { APIContext } from 'astro';
import { AuthTokenExpiredError, expiredToken, isAuthorized, unauthorized } from '../../lib/auth';
import { resolveSecret } from '../../lib/secrets';
import * as uint8arrays from 'uint8arrays';

export const prerender = false;

/**
 * com.atproto.identity.getRecommendedDidCredentials
 *
 * Returns the recommended DID credentials for the current account.
 * This includes the handle, signing key, and PDS endpoint that should be
 * used when updating the PLC identity.
 */
export async function GET({ locals, request }: APIContext) {
  const { env } = locals.runtime;

  try {
    if (!(await isAuthorized(request, env))) return unauthorized();
  } catch (err) {
    if (err instanceof AuthTokenExpiredError) {
      return expiredToken();
    }
    throw err;
  }

  try {
    const handle = (await resolveSecret(env.PDS_HANDLE)) ?? 'example.com';
    const hostname = env.PDS_HOSTNAME ?? handle;

    // Always ES256K: derive did:key from the secp256k1 signing key
    let didKey: string | undefined;
    const priv = (await resolveSecret((env as any).REPO_SIGNING_KEY))?.trim();
    if (!priv) {
      return new Response(
        JSON.stringify({ error: 'InvalidRequest', message: 'REPO_SIGNING_KEY not configured for ES256K' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      );
    }
    try {
      const { Secp256k1Keypair } = await import('@atproto/crypto');
      let kp: any;
      if (/^[0-9a-fA-F]{64}$/.test(priv)) {
        kp = await Secp256k1Keypair.import(priv);
      } else {
        const bin = atob(priv.replace(/\s+/g, ''));
        const bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        kp = await Secp256k1Keypair.import(bytes);
      }
      didKey = kp.did();
    } catch (e) {
      return new Response(
        JSON.stringify({ error: 'InvalidRequest', message: 'Failed to derive secp256k1 did:key from REPO_SIGNING_KEY' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      );
    }

    // Get current PLC data to preserve rotation keys
    const did = await resolveSecret(env.PDS_DID);
    if (!did) {
      return new Response(JSON.stringify({ error: 'InvalidRequest', message: 'PDS_DID is not configured' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
    }
    const plcResponse = await fetch(`https://plc.directory/${did}/data`);

    let rotationKeys: string[] = [];
    if (plcResponse.ok) {
      const plcData = await plcResponse.json() as { rotationKeys?: string[] };
      rotationKeys = plcData.rotationKeys || [];
    }

    const credentials = {
      rotationKeys,
      alsoKnownAs: [`at://${handle}`],
      verificationMethods: { atproto: didKey },
      services: {
        atproto_pds: {
          type: 'AtprotoPersonalDataServer',
          endpoint: `https://${hostname}`
        }
      }
    };

    return new Response(
      JSON.stringify(credentials),
      { status: 200, headers: { 'Content-Type': 'application/json' } }
    );
  } catch (error: any) {
    console.error('Get recommended credentials error:', error);
    return new Response(
      JSON.stringify({
        error: 'InternalServerError',
        message: error.message || 'Failed to get recommended credentials'
      }),
      { status: 500, headers: { 'Content-Type': 'application/json' } }
    );
  }
}
