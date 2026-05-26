import type { APIContext } from "astro";
import { requireDebugRequest } from "../../../lib/debug-policy";

export const prerender = false;

function blobKey(param: string | undefined): string | null {
  return param && param.length > 0 ? param : null;
}

export async function GET({ locals, params, request }: APIContext) {
  const { env } = locals;
  const denied = await requireDebugRequest(env, request);
  if (denied) return denied;

  const key = blobKey(params.key);
  if (!key) return new Response("missing key", { status: 400 });

  const obj = await env.ALTERAN_BLOBS.get(key);
  if (!obj) return new Response("not found", { status: 404 });

  const body = obj.body as unknown as BodyInit | null;
  return new Response(body ?? undefined, {
    headers: {
      "content-type": obj.httpMetadata?.contentType ??
        "application/octet-stream",
    },
  });
}

export async function PUT({ locals, request, params }: APIContext) {
  const { env } = locals;
  const denied = await requireDebugRequest(env, request);
  if (denied) return denied;

  const key = blobKey(params.key);
  if (!key) return new Response("missing key", { status: 400 });

  const body = request.body;
  if (!body) return new Response("missing body", { status: 400 });
  await env.ALTERAN_BLOBS.put(key, body, {
    httpMetadata: {
      contentType: request.headers.get("content-type") ??
        "application/octet-stream",
    },
  });
  return new Response("uploaded");
}
