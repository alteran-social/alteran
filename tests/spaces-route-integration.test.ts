import { expect } from '@std/expect';
import alteran from '../index.js';

Deno.test('external Astro integrations receive the supported Space routes', () => {
  const routes: { pattern: string; entrypoint: string }[] = [];
  alteran().hooks['astro:config:setup']({
    config: { output: 'server', root: new URL('file:///tmp/alteran-consumer/') },
    updateConfig: () => {},
    addMiddleware: () => {},
    injectRoute: (route: { pattern: string; entrypoint: string }) => routes.push(route),
    logger: {},
  });
  const spaceRoutes = routes.filter((route) => route.pattern.startsWith('/xrpc/com.atproto.space.'));
  expect(spaceRoutes.map(({ pattern }) => pattern)).toEqual([
    '/xrpc/com.atproto.space.getRecord', '/xrpc/com.atproto.space.listRecords',
  ]);
  for (const route of spaceRoutes) {
    const name = route.pattern.slice('/xrpc/'.length);
    expect(route.entrypoint.endsWith(`/src/pages/xrpc/${name}.ts`)).toBe(true);
  }
});
