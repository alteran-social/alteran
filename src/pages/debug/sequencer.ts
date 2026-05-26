import type { APIContext } from "astro";
import { fetchSequencerDebugMetrics } from "../../lib/debug-sequencer";

export const prerender = false;

export async function GET({ locals, request }: APIContext) {
  return fetchSequencerDebugMetrics(locals.env, request);
}
