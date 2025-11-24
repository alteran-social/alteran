import type { APIContext } from 'astro';
import { AuthTokenExpiredError, authenticateRequest, expiredToken, unauthorized } from '../../lib/auth';
import { getAccountByIdentifier } from '../../db/account';

export const prerender = false;

/**
 * com.atproto.server.getSession
 * Get information about the current session
 */
export async function GET({ locals, request }: APIContext) {
  const { env } = locals.runtime;

  // Validate the access token
  let authContext;
  try {
    authContext = await authenticateRequest(request, env);
  } catch (err) {
    if (err instanceof AuthTokenExpiredError) {
      return expiredToken();
    }
    throw err;
  }
  if (!authContext) {
    return unauthorized();
  }

  const did = authContext.claims.sub;
  const account = await getAccountByIdentifier(env, did);
  const handle = account?.handle ?? (env.PDS_HANDLE as string) ?? 'user.example.com';

  return new Response(
    JSON.stringify({
      did,
      handle,
      email: account?.email ?? 'user@example.com',
      emailConfirmed: true,
      emailAuthFactor: false,
      didDoc: {
        '@context': ['https://www.w3.org/ns/did/v1'],
        id: did,
        alsoKnownAs: [`at://${handle}`],
        verificationMethod: [],
        service: [
          {
            id: '#atproto_pds',
            type: 'AtprotoPersonalDataServer',
            serviceEndpoint: `https://${env.PDS_HOSTNAME ?? handle}`,
          },
        ],
      },
    }),
    {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
      },
    }
  );
};
