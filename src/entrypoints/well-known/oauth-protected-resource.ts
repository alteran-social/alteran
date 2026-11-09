import type { APIContext } from "astro";
import { CACHE_CONFIGS, withCache } from "../../lib/cache";
import { publicPdsOrigin } from "../../lib/oauth/consent";
import { OAUTH_SCOPES_SUPPORTED } from "../../lib/oauth/scopes-supported";

export const prerender = false;

export async function GET({ locals, request }: APIContext) {
  const { env } = locals;
  return withCache(
    request,
    async () => {
      const origin = publicPdsOrigin(env, request);
      const json = {
        resource: origin,
        authorization_servers: [origin],
        bearer_methods_supported: ["header"],
        scopes_supported: OAUTH_SCOPES_SUPPORTED,
        resource_documentation:
          `${origin}/.well-known/oauth-protected-resource`,
      };
      return new Response(JSON.stringify(json, null, 2), {
        headers: { "Content-Type": "application/json" },
      });
    },
    CACHE_CONFIGS.WELL_KNOWN,
  );
}
