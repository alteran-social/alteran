import type { APIContext } from 'astro';
import { readJson } from '../../lib/util';
import { authenticateRequest } from '../../lib/auth';
import { canAccessFullAccount } from '../../lib/auth-scope';
import { hashPassword } from '../../lib/password';
import { generateAppPasswordSecret } from '../../lib/app-password';
import { createAppPasswordRow } from '../../db/app-password';

export const prerender = false;

const MAX_NAME_LEN = 64;

function isUniqueConstraintViolation(error: unknown): boolean {
  const messages: string[] = [];
  let current: unknown = error;
  while (current instanceof Error) {
    messages.push(current.message);
    current = (current as { cause?: unknown }).cause;
  }
  return messages.some((message) => /UNIQUE constraint failed/i.test(message));
}

export async function POST({ locals, request }: APIContext) {
  const { env } = locals.runtime;
  const auth = await authenticateRequest(request, env).catch(() => null);
  if (!auth || !canAccessFullAccount(auth.access)) {
    return new Response(JSON.stringify({ error: 'AuthRequired', message: 'Full-access session required' }), {
      status: 401, headers: { 'Content-Type': 'application/json' },
    });
  }

  const raw = await readJson(request).catch(() => ({}));
  const body = (raw ?? {}) as { name?: unknown; privileged?: unknown };
  const name = typeof body.name === 'string' ? body.name.trim() : '';
  const privileged = body.privileged === true;
  if (!name || name.length > MAX_NAME_LEN) {
    return new Response(JSON.stringify({ error: 'InvalidRequest', message: 'name is required and must be at most 64 characters' }), {
      status: 400, headers: { 'Content-Type': 'application/json' },
    });
  }

  const did = auth.claims.sub;
  const secret = generateAppPasswordSecret();
  let created: Awaited<ReturnType<typeof createAppPasswordRow>>;
  try {
    created = await createAppPasswordRow(env, {
      did,
      name,
      passwordScrypt: await hashPassword(secret),
      privileged,
    });
  } catch (error) {
    // D1 surfaces the (did, name) primary-key violation as a UNIQUE constraint
    // error; collapse it to the same InvalidRequest a pre-check would have
    // returned, and avoid the TOCTOU between check and insert. Drizzle wraps
    // the underlying D1 error in `error.cause`.
    if (isUniqueConstraintViolation(error)) {
      return new Response(JSON.stringify({ error: 'InvalidRequest', message: 'app password with this name already exists' }), {
        status: 400, headers: { 'Content-Type': 'application/json' },
      });
    }
    throw error;
  }

  return new Response(JSON.stringify({
    name: created.name,
    password: secret,
    privileged: created.privileged,
    createdAt: new Date(created.createdAt * 1000).toISOString(),
  }), { status: 200, headers: { 'Content-Type': 'application/json' } });
}
