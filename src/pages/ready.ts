import type { APIContext } from 'astro';
import { checkRuntimeDependencies, runtimeDependenciesHealthy } from '../lib/health';

export const prerender = false;

export async function GET({ locals }: APIContext) {
  const { env } = locals.runtime;
  const checks = await checkRuntimeDependencies(env);

  if (runtimeDependenciesHealthy(checks)) {
    return new Response('ok', {
      headers: { 'Content-Type': 'text/plain; charset=utf-8' },
    });
  }

  return new Response(JSON.stringify({ status: 'unhealthy', checks }, null, 2), {
    status: 503,
    headers: { 'Content-Type': 'application/json' },
  });
}
