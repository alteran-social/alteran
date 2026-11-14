import { parseSpaceRef } from '../../db/space-ref';

/** Capture the one canonical authority-policy target of a getSpace request. */
export function parseGetSpaceRequest(request: Request): string | null {
  if (request.method !== 'GET' || request.signal.aborted || request.url.length > 16_384) return null;
  const url = new URL(request.url);
  if (url.pathname !== '/xrpc/com.atproto.space.getSpace' ||
    Array.from(url.searchParams.keys()).some((key) => key !== 'space')) return null;
  const values = url.searchParams.getAll('space');
  if (values.length !== 1) return null;
  try {
    return parseSpaceRef(values[0]).ref;
  } catch {
    return null;
  }
}
