import type { APIContext } from 'astro';

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
  const checks: HealthCheck['checks'] = {
    database: { status: 'ok' },
    storage: { status: 'ok' },
  };

  let overallStatus: 'healthy' | 'unhealthy' = 'healthy';

  // Check D1 database connectivity
  try {
    if (env.ALTERAN_DB) {
      await env.ALTERAN_DB.prepare('SELECT 1').first();
      checks.database.status = 'ok';
    } else {
      checks.database.status = 'error';
      checks.database.message = 'Database not configured';
      overallStatus = 'unhealthy';
    }
  } catch (error) {
    checks.database.status = 'error';
    checks.database.message = error instanceof Error ? error.message : 'Database connection failed';
    overallStatus = 'unhealthy';
  }

  // Check R2 storage connectivity
  try {
    if (env.ALTERAN_BLOBS) {
      // Simple list operation to verify connectivity
      await env.ALTERAN_BLOBS.list({ limit: 1 });
      checks.storage.status = 'ok';
    } else {
      checks.storage.status = 'error';
      checks.storage.message = 'Storage not configured';
      overallStatus = 'unhealthy';
    }
  } catch (error) {
    checks.storage.status = 'error';
    checks.storage.message = error instanceof Error ? error.message : 'Storage connection failed';
    overallStatus = 'unhealthy';
  }

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