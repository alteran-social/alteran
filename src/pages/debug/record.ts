import type { APIContext } from "astro";
import {
  getRecord as dalGetRecord,
  putRecord as dalPutRecord,
} from "../../db/dal";
import { requireDebugRequest } from "../../lib/debug-policy";

export const prerender = false;

export async function GET({ locals, request }: APIContext) {
  const { env } = locals;
  const denied = await requireDebugRequest(env, request);
  if (denied) return denied;

  const url = new URL(request.url);
  const uri = url.searchParams.get("uri");
  if (!uri) return new Response("missing uri", { status: 400 });

  const row = await dalGetRecord(env, uri);
  if (!row) return new Response("not found", { status: 404 });

  return new Response(JSON.stringify(row), {
    headers: { "Content-Type": "application/json" },
  });
}

export async function POST({ locals, request }: APIContext) {
  const { env } = locals;
  const denied = await requireDebugRequest(env, request);
  if (denied) return denied;

  const body = (await request.json()) as { uri?: string; json?: unknown };
  const uri = body.uri;
  if (!uri) return new Response("missing uri", { status: 400 });

  const did = env.PDS_DID as string;
  const row = {
    uri,
    did,
    cid: "cid-dev",
    json: JSON.stringify(body.json ?? { hello: "world" }),
  };
  await dalPutRecord(env, row);
  return new Response(JSON.stringify({ ok: true }), {
    headers: { "Content-Type": "application/json" },
  });
}
