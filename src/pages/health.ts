import type { APIContext } from 'astro';
import { checkRuntimeDependencies, runtimeDependenciesHealthy } from '../lib/health';

export const prerender = false;

interface HealthCheck {
  status: 'healthy' | 'unhealthy';
  timestamp: string;
  checks: {
    database: { status: 'ok' | 'error'; message?: string };
    storage: { status: 'ok' | 'error'; message?: string };
  };
}

export async function GET({ locals }: APIContext) {
  const { env } = locals.runtime;
  const checks = await checkRuntimeDependencies(env);
  const overallStatus: HealthCheck['status'] = runtimeDependenciesHealthy(checks) ? 'healthy' : 'unhealthy';

  const response: HealthCheck = {
    status: overallStatus,
    timestamp: new Date().toISOString(),
    checks,
  };

  const status = overallStatus === 'healthy' ? 200 : 503;

  return new Response(JSON.stringify(response, null, 2), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
