import type { Env } from "../env";
import { DEBUG_SEQUENCER_ROUTE } from "../../route-registry.js";
import { fetchSequencerDebugMetrics } from "../lib/debug-sequencer";

export async function handleWorkerDebugRoute(
  env: Env,
  request: Request,
): Promise<Response | null> {
  const url = new URL(request.url);
  if (url.pathname !== DEBUG_SEQUENCER_ROUTE || request.method !== "GET") {
    return null;
  }

  return fetchSequencerDebugMetrics(env, request);
}
