import type { APIContext } from 'astro';
import { authErrorResponse, authenticateRequest, unauthorized } from '../../lib/auth';
import { canAccessChat } from '../../lib/auth-scope';
import { getPrimaryActor } from '../../lib/actor';
import { listChatConvoLogs } from '../../lib/chat';

export const prerender = false;

export async function GET({ locals, request }: APIContext) {
  const { env } = locals;
  try {
    const auth = await authenticateRequest(request, env);
    if (!auth || !canAccessChat(auth.access)) return unauthorized();
  } catch (error) {
    const handled = await authErrorResponse(env, error);
    if (handled) return handled;
    throw error;
  }

  const url = new URL(request.url);
  const cursorParam = url.searchParams.get('cursor');
  const parsedCursor = Number.parseInt(cursorParam ?? '', 10);
  const cursor = Number.isFinite(parsedCursor) ? parsedCursor : undefined;

  const actor = await getPrimaryActor(env);
  const { logs, cursor: nextCursor } = await listChatConvoLogs(env, actor.did, cursor);

  const payload: Record<string, unknown> = { logs };
  if (nextCursor) payload.cursor = nextCursor;

  return new Response(JSON.stringify(payload), {
    headers: { 'Content-Type': 'application/json' },
  });
}
