import { expect } from '@std/expect';
import alteran from '../index.js';

Deno.test('external Astro integrations receive only the supported Space route', () => {
  const routes: { pattern: string; entrypoint: string }[] = [];
  alteran().hooks['astro:config:setup']({
    config: { output: 'server', root: new URL('file:///tmp/alteran-consumer/') },
    updateConfig: () => {},
    addMiddleware: () => {},
    injectRoute: (route: { pattern: string; entrypoint: string }) => routes.push(route),
    logger: {},
  });
  const spaceRoutes = routes.filter((route) => route.pattern.startsWith('/xrpc/com.atproto.space.'));
  expect(spaceRoutes).toHaveLength(1);
  expect(spaceRoutes[0].pattern).toBe('/xrpc/com.atproto.space.getRecord');
  expect(spaceRoutes[0].entrypoint.endsWith('/src/pages/xrpc/com.atproto.space.getRecord.ts')).toBe(true);
});
