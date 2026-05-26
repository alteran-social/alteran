import type { Env } from "../env";
import {
  isLocalHostname,
  parsePublicOrigin,
  requestHostname,
} from "./public-host";
import { resolveSecret } from "./secrets";

function bearerToken(request: Request): string | null {
  const authorization = request.headers.get("authorization") ?? "";
  const match = /^Bearer\s+(.+)$/i.exec(authorization);
  return match ? match[1] : null;
}

async function hasDebugToken(env: Env, request: Request): Promise<boolean> {
  const configuredToken = await resolveSecret(env.PDS_DEBUG_TOKEN);
  const suppliedToken = bearerToken(request);
  return !!configuredToken && suppliedToken === configuredToken;
}

function isLocalRequest(env: Env, request: Request): boolean {
  if (env.ENVIRONMENT === "production") return false;

  const hostname = requestHostname(request);
  if (!hostname || !isLocalHostname(hostname)) return false;

  const configuredHostname = env.PDS_HOSTNAME;
  if (!configuredHostname) return true;

  const parsed = parsePublicOrigin(configuredHostname);
  return !!parsed && isLocalHostname(parsed.hostname);
}

export async function isDebugRequestAllowed(
  env: Env,
  request: Request,
): Promise<boolean> {
  try {
    return (await hasDebugToken(env, request)) || isLocalRequest(env, request);
  } catch {
    return false;
  }
}

export function debugRouteNotFound(): Response {
  return new Response("Not Found", { status: 404 });
}

export async function requireDebugRequest(
  env: Env,
  request: Request,
): Promise<Response | null> {
  return (await isDebugRequestAllowed(env, request))
    ? null
    : debugRouteNotFound();
}
