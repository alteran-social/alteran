import type { APIContext } from 'astro';
import { withCache, CACHE_CONFIGS } from '../../lib/cache';
import { publicPdsOrigin } from '../../lib/oauth/consent';

export const prerender = false;

export async function GET({ locals, request }: APIContext) {
  const { env } = locals.runtime;
  return withCache(
    request,
    async () => {
      const origin = publicPdsOrigin(env, request);
      const json = {
        issuer: origin,
        pushed_authorization_request_endpoint: `${origin}/oauth/par`,
        authorization_endpoint: `${origin}/oauth/authorize`,
        token_endpoint: `${origin}/oauth/token`,
        jwks_uri: `${origin}/oauth/jwks`,
        revocation_endpoint: `${origin}/oauth/revoke`,
        scopes_supported: ['atproto', 'transition:generic'],
        response_types_supported: ['code'],
        response_modes_supported: ['query'],
        grant_types_supported: ['authorization_code', 'refresh_token'],
        code_challenge_methods_supported: ['S256'],
        token_endpoint_auth_methods_supported: ['none', 'private_key_jwt'],
        token_endpoint_auth_signing_alg_values_supported: ['ES256'],
        dpop_signing_alg_values_supported: ['ES256'],
        subject_types_supported: ['public'],
        prompt_values_supported: ['none', 'consent', 'login'],
        require_pushed_authorization_requests: true,
        request_parameter_supported: false,
        request_uri_parameter_supported: true,
        require_request_uri_registration: false,
        authorization_response_iss_parameter_supported: true,
        client_id_metadata_document_supported: true,
        protected_resources: [origin],
      };
      return new Response(JSON.stringify(json, null, 2), {
        headers: { 'Content-Type': 'application/json' },
      });
    },
    CACHE_CONFIGS.WELL_KNOWN,
  );
}
