import type { APIContext } from "astro";
import { redirectWellKnownAlias } from "../../lib/well-known-redirect";

export const prerender = false;

export function GET({ request }: APIContext) {
  return redirectWellKnownAlias(request) ??
    new Response("NotFound", { status: 404 });
}
