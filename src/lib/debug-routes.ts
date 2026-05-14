import type { Env } from '../env';

const LOCALHOSTS = new Set(['localhost', '::1', '[::1]']);

export function isDebugRouteAllowed(env: Env, request: Request): boolean {
  if ((env.ENVIRONMENT as string | undefined) === 'production') return false;

  const hostname = new URL(request.url).hostname;
  return LOCALHOSTS.has(hostname) || isLoopbackIpv4(hostname);
}

export function debugNotFound(): Response {
  return new Response('Not Found', { status: 404 });
}

function isLoopbackIpv4(hostname: string): boolean {
  const octets = hostname.split('.');
  if (octets.length !== 4 || octets[0] !== '127') return false;
  return octets.every((octet) => /^\d+$/.test(octet) && Number(octet) >= 0 && Number(octet) <= 255);
}
