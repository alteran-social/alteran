import type { APIContext } from 'astro';
import { AuthTokenExpiredError, expiredToken, isAuthorized, unauthorized } from '../../lib/auth';
import { resolveSecret } from '../../lib/secrets';

export const prerender = false;

/**
 * com.atproto.identity.submitPlcOperation
 *
 * Submits a signed PLC operation to the PLC directory.
 * This is a proxy endpoint that validates the operation is for the current account
 * before submitting it to plc.directory.
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
    const body = await request.json() as { operation?: any };
    const { operation } = body;

    if (!operation) {
      return new Response(
        JSON.stringify({
          error: 'InvalidRequest',
          message: 'Missing operation in request body'
        }),
        { status: 400, headers: { 'Content-Type': 'application/json' } }
      );
    }

    const did = await resolveSecret(env.PDS_DID);
    if (!did) {
      return new Response(
        JSON.stringify({ error: 'InvalidRequest', message: 'PDS_DID is not configured' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } }
      );
    }

    console.log('Submitting PLC operation:', {
      did,
      operationType: operation.type,
      hasSig: !!operation.sig,
      prev: operation.prev
    });

    // Submit to PLC directory
    const plcResponse = await fetch(`https://plc.directory/${did}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(operation)
    });

    const responseHeaders: Record<string, string> = {};
    plcResponse.headers.forEach((value, key) => {
      responseHeaders[key] = value;
    });

    console.log('PLC response:', {
      status: plcResponse.status,
      statusText: plcResponse.statusText,
      headers: responseHeaders
    });

    if (!plcResponse.ok) {
      const errorText = await plcResponse.text();
      console.error('PLC directory error:', errorText);
      return new Response(
        JSON.stringify({
          error: 'PlcOperationFailed',
          message: `PLC directory rejected operation (${plcResponse.status}): ${errorText}`
        }),
        { status: plcResponse.status, headers: { 'Content-Type': 'application/json' } }
      );
    }

    const plcResult = await plcResponse.text();
    console.log('PLC submission successful:', plcResult);

    return new Response(
      JSON.stringify({ success: true }),
      { status: 200, headers: { 'Content-Type': 'application/json' } }
    );
  } catch (error: any) {
    console.error('Submit PLC operation error:', error);
    return new Response(
      JSON.stringify({
        error: 'InternalServerError',
        message: error.message || 'Failed to submit PLC operation'
      }),
      { status: 500, headers: { 'Content-Type': 'application/json' } }
    );
  }
}
