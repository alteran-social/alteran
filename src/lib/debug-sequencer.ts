import type { Env } from "../env";
import { requireDebugRequest } from "./debug-policy";
import { errorMessage } from "./errors";

export async function fetchSequencerDebugMetrics(
  env: Env,
  request: Request,
): Promise<Response> {
  const denied = await requireDebugRequest(env, request);
  if (denied) return denied;

  const sequencer = env.ALTERAN_SEQUENCER;
  if (!sequencer) {
    return jsonResponse({ error: "SequencerNotConfigured" }, 503);
  }

  try {
    const id = sequencer.idFromName("default");
    const stub = sequencer.get(id);
    const proxyRequest = new Request(
      new URL("/metrics", request.url).toString(),
      {
        method: "GET",
      },
    );
    const response = await stub.fetch(proxyRequest);
    const headers = new Headers(response.headers);
    headers.set("Content-Type", "application/json");
    return new Response(await response.text(), {
      status: response.status,
      headers,
    });
  } catch (error) {
    return jsonResponse({
      error: "InternalError",
      message: String(errorMessage(error) || error),
    }, 500);
  }
}

function jsonResponse(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
