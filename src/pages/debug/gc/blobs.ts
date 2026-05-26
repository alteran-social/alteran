import type { APIContext } from "astro";
import {
  deleteUnreferencedBlobKeys,
  listOrphanBlobRefs,
} from "../../../db/dal";
import { requireDebugRequest } from "../../../lib/debug-policy";

export const prerender = false;

export async function POST({ locals, request }: APIContext) {
  const { env } = locals;
  const denied = await requireDebugRequest(env, request);
  if (denied) return denied;

  const deleted = await deleteUnreferencedBlobKeys(
    env,
    await listOrphanBlobRefs(env),
  );
  return new Response(JSON.stringify({ deleted }), {
    headers: { "Content-Type": "application/json" },
  });
}
