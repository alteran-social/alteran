import type { APIContext } from 'astro';
import { AuthTokenExpiredError, expiredToken, isAuthorized, unauthorized } from '../../lib/auth';
import { resolveSecret } from '../../lib/secrets';

export const prerender = false;

/**
 * com.atproto.identity.signPlcOperation
 *
 * Signs a PLC update operation with the server's PLC rotation key and returns it
 * to the caller. This endpoint mirrors the behavior of a PDS that controls the
 * PLC rotation key directly (single-user deployments), so the email challenge
 * token is accepted but not enforced here.
 */
export async function POST({ locals, request }: APIContext) {
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
    const body = await request.json() as {
      token?: string;
      rotationKeys?: string[];
      alsoKnownAs?: string[];
      verificationMethods?: Record<string, string>;
      services?: Record<string, { type: string; endpoint: string }>;
    };

    // NOTE: For single-user PDS we don't enforce email token checks.
    if (!body || typeof body !== 'object') {
      return jsonErr(400, 'InvalidRequest', 'Malformed JSON body');
    }

    const did = (await resolveSecret(env.PDS_DID)) ?? '';
    if (!did || !did.startsWith('did:')) {
      return jsonErr(400, 'InvalidRequest', 'PDS_DID is not configured');
    }

    // Load PLC rotation key (hex-encoded secp256k1 private key).
    // MUST be the rotation key currently present in the PLC document.
    const privHex = ((await resolveSecret(env.PDS_PLC_ROTATION_KEY as any)) || '').trim();
    if (!privHex) {
      return jsonErr(500, 'ServerMisconfigured', 'PDS_PLC_ROTATION_KEY is not configured');
    }
    // Lazy-load deps compatible with Workers runtime
    const { Secp256k1Keypair } = await import('@atproto/crypto');
    const dagCbor: any = await import('@ipld/dag-cbor');
    const { sha256 } = await import('multiformats/hashes/sha2');
    const { CID } = await import('multiformats/cid');
    const u8a: any = await import('uint8arrays');

    const signer = await Secp256k1Keypair.import(privHex);

    // Fetch last op for prev CID
    const lastRes = await fetch(`https://plc.directory/${encodeURIComponent(did)}/log/last`);
    if (!lastRes.ok) {
      const text = await lastRes.text();
      return jsonErr(lastRes.status, 'PlcFetchFailed', `Failed to fetch last op: ${text}`);
    }
    const lastOp = await lastRes.json();
    if ((lastOp as any)?.type === 'plc_tombstone') {
      return jsonErr(400, 'DidTombstoned', 'DID is tombstoned');
    }
    const lastOpCbor = dagCbor.encode(lastOp);
    const mh = await sha256.digest(lastOpCbor);
    const prevCid = CID.createV1(dagCbor.code, mh);

    // Fetch current document data as defaults and to verify rotation key
    const dataRes = await fetch(`https://plc.directory/${encodeURIComponent(did)}/data`);
    if (!dataRes.ok) {
      const text = await dataRes.text();
      return jsonErr(dataRes.status, 'PlcFetchFailed', `Failed to fetch document data: ${text}`);
    }
    const doc = (await dataRes.json()) as any;

    const rotationKeys = body.rotationKeys ?? doc.rotationKeys ?? [];
    const alsoKnownAs = body.alsoKnownAs ?? doc.alsoKnownAs ?? [];
    const verificationMethods = body.verificationMethods ?? doc.verificationMethods ?? {};
    const services = body.services ?? doc.services ?? {};

    if (!services.atproto_pds || typeof services.atproto_pds !== 'object') {
      return jsonErr(400, 'InvalidRequest', 'Missing atproto_pds service in PLC operation');
    }
    if (!services.atproto_pds.type) {
      services.atproto_pds.type = 'AtprotoPersonalDataServer';
    }

    const unsignedOp = {
      type: 'plc_operation',
      rotationKeys,
      verificationMethods,
      alsoKnownAs,
      services,
      prev: prevCid.toString(),
    } as Record<string, unknown>;

    const bytes = dagCbor.encode(unsignedOp);
    const sig = await signer.sign(bytes);
    const sigB64 = (u8a.toString as any)(sig, 'base64url');
    const operation = { ...unsignedOp, sig: sigB64 };

    // sanity: ensure our configured rotation key is included
    const signerDid = (await (await import('@atproto/crypto')).Secp256k1Keypair.import(privHex)).did();
    if (!rotationKeys.includes(signerDid)) {
      return jsonErr(
        400,
        'RotationKeyMismatch',
        `Configured PDS_PLC_ROTATION_KEY (${signerDid}) is not present in PLC rotationKeys. Update PLC or your configuration.`,
      );
    }

    return new Response(JSON.stringify({ operation }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (error: any) {
    console.error('signPlcOperation error:', error);
    return jsonErr(500, 'InternalServerError', error?.message || 'Failed to sign PLC operation');
  }
}

function jsonErr(status: number, error: string, message: string) {
  return new Response(
    JSON.stringify({ error, message }),
    { status, headers: { 'Content-Type': 'application/json' } }
  );
}
