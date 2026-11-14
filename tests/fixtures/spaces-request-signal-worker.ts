import { normalizePdsRequestForAstro } from '../../src/worker/normalize-request';

const observations = new Map<string, { original: boolean; normalized: boolean }>();

export default {
  async fetch(request: Request, _env: unknown, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const id = url.searchParams.get('id') ?? '';
    if (url.pathname === '/status') return Response.json(observations.get(id) ?? null);
    const normalized = normalizePdsRequestForAstro(request as never) as unknown as Request;
    const observation = { original: false, normalized: false };
    observations.set(id, observation);
    const originalAbort = new Promise<void>((resolve) => request.signal.addEventListener('abort', () => {
      observation.original = request.signal.aborted;
      resolve();
    }, { once: true }));
    const normalizedAbort = new Promise<void>((resolve) => normalized.signal.addEventListener('abort', () => {
      observation.normalized = normalized.signal.aborted;
      resolve();
    }, { once: true }));
    ctx.waitUntil(Promise.all([originalAbort, normalizedAbort]));
    await new Promise((resolve) => setTimeout(resolve, 8000));
    return new Response('done');
  },
};
