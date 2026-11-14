import { expect } from '@std/expect';
import { Miniflare } from 'miniflare';
import { join } from 'node:path';
import { build } from 'esbuild';

Deno.test({
  name: 'private Space errors are sanitized at the composed Worker entrypoint',
  sanitizeOps: false,
  sanitizeResources: false,
  async fn() {
    const root = join(import.meta.dirname!, '..');
    const temp = await Deno.makeTempDir({ prefix: 'alteran-private-entry-' });
    const bundle = join(temp, 'worker.mjs');
    const handler = join(temp, 'handler.js');
    const seed = join(temp, 'seed.js');
    const astroEnv = join(temp, 'astro-env.js');
    await Deno.writeTextFile(handler, `export async function handle(req) {
      const mode = req.headers.get('x-test-mode');
      if (mode === 'handler-throws') throw new Error('private-entry-secret');
      if (mode === 'handler-500') return new Response('private-entry-secret', {
        status: 503, headers: { vary: '*', 'retry-after': '12345678', 'x-private': 'private-entry-secret' },
      });
      if (mode === 'challenge') return new Response('denied', { status: 401, headers: {
        vary: 'Origin', 'www-authenticate': 'DPoP', 'dpop-nonce': 'example-nonce',
      } });
      return new Response(req.method === 'HEAD' ? null : 'ok', { status: 200 });
    }`);
    await Deno.writeTextFile(seed, `export async function seed(_db, did) {
      if (did === 'did:example:seedfailure') throw new Error('private-entry-secret');
    }`);
    await Deno.writeTextFile(astroEnv, 'export function getSecret() { return undefined; }\n');
    await build({
      absWorkingDir: root, entryPoints: ['tests/fixtures/spaces-private-entry-worker.ts'],
      bundle: true, format: 'esm', platform: 'browser', outfile: bundle,
      external: ['node:*', 'cloudflare:workers'],
      alias: { '@astrojs/cloudflare/handler': handler, 'astro:env/server': astroEnv },
      plugins: [{ name: 'test-seed', setup(builder) {
        builder.onResolve({ filter: /^\.\.\/db\/seed$/ }, () => ({ path: seed }));
      } }],
      logLevel: 'silent',
    });
    const worker = new Miniflare({ modules: true, scriptPath: bundle, modulesRoot: temp,
      compatibilityDate: '2025-10-02', compatibilityFlags: ['nodejs_compat'],
      bindings: { PDS_DID: 'did:example:test', PDS_HANDLE: 'test.example', PDS_RELAY_NOTIFY: 'false' },
    });
    try {
      const paths = ['/xrpc/com.atproto.space.getRecord', '//xrpc/com.atproto.space.getRecord',
        '/pds/xrpc/com.atproto.memberspace.listMembers', '/xr%70c/com.atproto.space.getRecord',
        '/oauth/par', '/pds/oauth/token'];
      for (const path of paths) {
        for (const mode of ['secret-throws', 'invalid-config', 'seed-throws', 'handler-throws', 'handler-500']) {
          const response = await worker.dispatchFetch(`https://pds.example${path}`, {
            headers: { origin: 'https://client.example', 'x-test-mode': mode },
          });
          expect(response.status).toBe(mode === 'handler-500' ? 503 : 500);
          expect(await response.text()).not.toContain('private-entry-secret');
          expect(response.headers.get('x-private')).toBeNull();
          expect(response.headers.get('cache-control')).toBe('private, no-store');
          expect(response.headers.get('access-control-allow-origin')).toBe('*');
          if (mode === 'handler-500') {
            expect(response.headers.get('vary')).toBe('*');
            expect(response.headers.get('retry-after')).toBeNull();
          }
        }
      }
      const path = `https://pds.example${paths[0]}`;
      const ok = await worker.dispatchFetch(path);
      expect(ok.status).toBe(200);
      expect(await ok.text()).toBe('ok');
      expect(ok.headers.get('cache-control')).toBe('private, no-store');
      const challenge = await worker.dispatchFetch(path, { headers: { 'x-test-mode': 'challenge' } });
      expect(challenge.status).toBe(401);
      const exposed = challenge.headers.get('access-control-expose-headers')?.toLowerCase() ?? '';
      expect(exposed).toContain('dpop-nonce');
      expect(exposed).toContain('www-authenticate');
      const head = await worker.dispatchFetch(path, { method: 'HEAD' });
      expect(head.status).toBe(200);
      expect(await head.text()).toBe('');
      const preflight = await worker.dispatchFetch(path, { method: 'OPTIONS', headers: {
        origin: 'https://client.example', 'access-control-request-method': 'GET',
        'access-control-request-headers': 'authorization,dpop,accept-signature',
      } });
      expect(preflight.status).toBe(204);
      expect(preflight.headers.get('cache-control')).toBe('private, no-store');
      const allowed = preflight.headers.get('access-control-allow-headers')?.toLowerCase().split(',').map((x) => x.trim()) ?? [];
      for (const header of ['authorization', 'dpop', 'accept-signature']) expect(allowed).toContain(header);
      const publicFailure = await worker.dispatchFetch('https://pds.example/xrpc/com.atproto.repo.getRecord', {
        headers: { 'x-test-mode': 'handler-500' },
      });
      expect(await publicFailure.text()).toBe('private-entry-secret');
      expect(publicFailure.headers.get('x-private')).toBe('private-entry-secret');
    } finally {
      await worker.dispose();
      await Deno.remove(temp, { recursive: true });
    }
  },
});
