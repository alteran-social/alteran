import type { APIContext } from 'astro';
import { authErrorResponse, authenticateRequest, unauthorized } from '../../lib/auth';
import { getAccountByIdentifier } from '../../db/account';
import { buildDidDocument } from '../../lib/did-document';

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
  } catch (error) {
    const handled = await authErrorResponse(env, error);
    if (handled) return handled;
    throw error;
  }
  if (!authContext) {
    return unauthorized();
  }

  const did = authContext.claims.sub;
  const account = await getAccountByIdentifier(env, did);
  const handle = account?.handle ?? (env.PDS_HANDLE as string) ?? 'user.example.com';
  const didDoc = await buildDidDocument(env, did, handle);

  return new Response(
    JSON.stringify({
      did,
      handle,
      email: account?.email ?? (env.PDS_EMAIL as string | undefined) ?? 'user@example.com',
      emailConfirmed: true,
      emailAuthFactor: false,
      didDoc,
    }),
    {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
      },
    }
  );
};
