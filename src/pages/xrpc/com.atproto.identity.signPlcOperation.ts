import type { APIContext } from 'astro';
import { authErrorResponse, authenticateRequest, unauthorized } from '../../lib/auth';
import { canAccessFullAccount } from '../../lib/auth-scope';
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

    const privHex = ((await resolveSecret(env.PDS_PLC_ROTATION_KEY)) || '').trim();
    if (!privHex) {
      return jsonErr(500, 'ServerMisconfigured', 'PDS_PLC_ROTATION_KEY is not configured');
    }
    const { Secp256k1Keypair } = await import('@atproto/crypto');
    const dagCbor = await import('@ipld/dag-cbor');
    const { sha256 } = await import('multiformats/hashes/sha2');
    const { CID } = await import('multiformats/cid');
    const u8a = await import('uint8arrays');

    const signer = await Secp256k1Keypair.import(privHex);

    const lastResponse = await fetch(`https://plc.directory/${encodeURIComponent(did)}/log/last`);
    if (!lastResponse.ok) {
      const text = await lastResponse.text();
      return jsonErr(lastResponse.status, 'PlcFetchFailed', `Failed to fetch last op: ${text}`);
    }
    const lastOp = (await lastResponse.json()) as { type?: string };
    if (lastOp?.type === 'plc_tombstone') {
      return jsonErr(400, 'DidTombstoned', 'DID is tombstoned');
    }
    const lastOpCbor = dagCbor.encode(lastOp);
    const mh = await sha256.digest(lastOpCbor);
    const prevCid = CID.createV1(dagCbor.code, mh);

    const dataResponse = await fetch(`https://plc.directory/${encodeURIComponent(did)}/data`);
    if (!dataResponse.ok) {
      const text = await dataResponse.text();
      return jsonErr(dataResponse.status, 'PlcFetchFailed', `Failed to fetch document data: ${text}`);
    }
    type PlcDoc = {
      rotationKeys?: string[];
      alsoKnownAs?: string[];
      verificationMethods?: Record<string, string>;
      services?: Record<string, { type?: string; endpoint?: string }>;
    };
    const doc = (await dataResponse.json()) as PlcDoc;

    const rotationKeys = body.rotationKeys ?? doc.rotationKeys ?? [];
    const alsoKnownAs = body.alsoKnownAs ?? doc.alsoKnownAs ?? [];
    const verificationMethods = body.verificationMethods ?? doc.verificationMethods ?? {};
    const services = (body.services ?? doc.services ?? {}) as Record<
      string,
      { type?: string; endpoint?: string }
    >;

    const pdsService = services.atproto_pds;
    if (!pdsService || typeof pdsService !== 'object') {
      return jsonErr(400, 'InvalidRequest', 'Missing atproto_pds service in PLC operation');
    }
    if (!pdsService.type) {
      pdsService.type = 'AtprotoPersonalDataServer';
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
    const sigB64 = u8a.toString(sig, 'base64url');
    const operation = { ...unsignedOp, sig: sigB64 };

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
  } catch (error) {
    console.error('signPlcOperation error:', error);
    const message = error instanceof Error ? error.message : 'Failed to sign PLC operation';
    return jsonErr(500, 'InternalServerError', message);
  }
}

function jsonErr(status: number, error: string, message: string) {
  return new Response(
    JSON.stringify({ error, message }),
    { status, headers: { 'Content-Type': 'application/json' } }
  );
}
