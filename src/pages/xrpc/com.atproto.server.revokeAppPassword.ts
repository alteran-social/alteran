import type { APIContext } from 'astro';
import { lexicons } from '@atproto/api';
import type { Env } from '../../env';
import { authErrorResponse, authenticateRequest, unauthorized } from '../../lib/auth';
import { canAccessFullAccount } from '../../lib/auth-scope';
import { readJson } from '../../lib/util';
import { jsonError } from '../../lib/repo-write-validation';
import { revokeAppPasswordRecord, revokeRefreshTokensForAppPassword } from '../../db/account';

export const prerender = false;

type RevokeAppPasswordInput = {
  name: string;
};

export async function POST({ locals, request }: APIContext) {
  const { env } = locals.runtime;
  const auth = await authenticateFullAccount(env, request);
  if (auth instanceof Response) return auth;

  const rawInput = await readJson(request).catch(() => null);
  let input: RevokeAppPasswordInput;
  try {
    input = lexicons.assertValidXrpcInput(
      'com.atproto.server.revokeAppPassword',
      rawInput,
    ) as RevokeAppPasswordInput;
  } catch (error) {
    return jsonError(
      'InvalidRequest',
      error instanceof Error ? error.message : 'invalid input',
    );
  }

  const name = input.name.trim();
  if (!name) return jsonError('InvalidRequest', 'name must not be empty');

  await revokeAppPasswordRecord(env, auth.claims.sub, name);
  await revokeRefreshTokensForAppPassword(env, auth.claims.sub, name);

  return new Response(JSON.stringify({}), {
    headers: { 'Content-Type': 'application/json' },
  });
}

async function authenticateFullAccount(env: Env, request: Request) {
  let auth;
  try {
    auth = await authenticateRequest(request, env);
  } catch (error) {
    const handled = await authErrorResponse(env, error);
    if (handled) return handled;
    throw error;
  }
  if (!auth) return unauthorized();
  if (auth.access.isTakendown) {
    return jsonError('AccountTakedown', 'Account has been taken down', 403);
  }
  if (!canAccessFullAccount(auth.access)) return unauthorized();
  return auth;
}
