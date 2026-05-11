export function createApp() {
  return {
    // Lazy-import the worker to avoid a hard dependency on Astro internals
    // during tests that just want the app shape.
    fetch: async (request: Request, env: unknown, ctx: ExecutionContext) => {
      const worker = await import('./_worker');
      // The Astro/Cloudflare workers-types collision means we can't express
      // this without a cast — the imported handler expects the
      // @cloudflare/workers-types Request which differs from the DOM Request.
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      return (worker as any).default.fetch(request, env, ctx);
    },
  } as const;
}
