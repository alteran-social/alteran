import type { Env } from '../env';

export type DependencyStatus = 'ok' | 'error';

export interface DependencyCheck {
  status: DependencyStatus;
  message?: string;
}

export interface RuntimeDependencyChecks {
  database: DependencyCheck;
  storage: DependencyCheck;
}

function errorMessage(error: unknown, fallback: string): string {
  return error instanceof Error ? error.message : fallback;
}

async function checkDatabase(env: Env): Promise<DependencyCheck> {
  if (!env.ALTERAN_DB) {
    return { status: 'error', message: 'Database not configured' };
  }

  try {
    await env.ALTERAN_DB.prepare('SELECT 1').first();
    return { status: 'ok' };
  } catch (error) {
    return { status: 'error', message: errorMessage(error, 'Database connection failed') };
  }
}

async function checkStorage(env: Env): Promise<DependencyCheck> {
  if (!env.ALTERAN_BLOBS) {
    return { status: 'error', message: 'Storage not configured' };
  }

  try {
    await env.ALTERAN_BLOBS.list({ limit: 1 });
    return { status: 'ok' };
  } catch (error) {
    return { status: 'error', message: errorMessage(error, 'Storage connection failed') };
  }
}

export async function checkRuntimeDependencies(env: Env): Promise<RuntimeDependencyChecks> {
  const [database, storage] = await Promise.all([
    checkDatabase(env),
    checkStorage(env),
  ]);

  return { database, storage };
}

export function runtimeDependenciesHealthy(checks: RuntimeDependencyChecks): boolean {
  return checks.database.status === 'ok' && checks.storage.status === 'ok';
}
