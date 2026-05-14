import type { APIContext } from 'astro';
import { routeNotFound } from '../../lib/local-xrpc';

export const prerender = false;

export async function GET(_ctx: APIContext) {
  return routeNotFound('com.atproto.sync.getBlocks.json is not a public ATProto XRPC route');
}
