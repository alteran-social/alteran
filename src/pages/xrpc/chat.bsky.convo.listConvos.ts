import type { APIContext } from 'astro';
import { authErrorResponse, authenticateRequest, unauthorized } from '../../lib/auth';
import { canAccessChat } from '../../lib/auth-scope';
import { listChatConvos } from '../../lib/chat';
import { getPrimaryActor } from '../../lib/actor';

export const prerender = false;

export async function GET({ locals, request }: APIContext) {
  const { env } = locals.runtime;
  try {
    const auth = await authenticateRequest(request, env);
    if (!auth || !canAccessChat(auth.access)) return unauthorized();
  } catch (error) {
    const handled = await authErrorResponse(env, error);
    if (handled) return handled;
    throw error;
  }

  const url = new URL(request.url);
  const limitInput = Number.parseInt(url.searchParams.get('limit') ?? '', 10);
  const limit = Math.max(1, Math.min(Number.isFinite(limitInput) ? limitInput : 50, 100));
  const cursorParam = url.searchParams.get('cursor');
  const cursor = cursorParam ? Number.parseInt(cursorParam, 10) : undefined;
  const readStateParam = url.searchParams.get('readState');
  const statusParam = url.searchParams.get('status');

  const filters = {
    readState: readStateParam === 'unread' ? 'unread' : null,
    status:
      statusParam === 'request' || statusParam === 'accepted' ? statusParam : null,
  } as const;

  const actor = await getPrimaryActor(env);
  const { convos, cursor: nextCursor } = await listChatConvos(env, actor.did, limit, cursor, filters);

  const payload: Record<string, unknown> = {
    convos,
  };
  if (nextCursor) payload.cursor = nextCursor;

  return new Response(JSON.stringify(payload), {
    headers: { 'Content-Type': 'application/json' },
  });
}
