import { expect } from '@std/expect';
import { Miniflare } from 'miniflare';
import { importJWK, SignJWT, type JWK } from 'jose';
import { join } from 'node:path';
import type { Env } from '../src/env';
import { sha256b64url } from '../src/lib/oauth/dpop';

Deno.test({
  name: 'built Astro worker routes an authorized private Space record',
  ignore: Deno.env.get('RUN_APP_TESTS') !== 'true',
  sanitizeOps: false,
  sanitizeResources: false,
  async fn() {
    const root = join(import.meta.dirname!, '..');
    const build = await new Deno.Command(Deno.execPath(), {
      cwd: root, args: ['task', 'build'], stdout: 'piped', stderr: 'piped',
    }).output();
    if (!build.success) throw new Error(`Astro build failed: ${new TextDecoder().decode(build.stderr)}`);

    const bindings = {
      PDS_DID: 'did:example:test', PDS_HANDLE: 'test.example', USER_PASSWORD: 'pwd',
      ACCESS_TOKEN: 'test-only-access-secret', REFRESH_TOKEN: 'test-only-refresh-secret',
      REFRESH_TOKEN_SECRET: 'test-only-refresh-secret', SESSION_JWT_SECRET: 'test-only-session-secret',
      PDS_RELAY_NOTIFY: 'false',
    };
    const modules: { type: 'ESModule'; path: string }[] = [{ type: 'ESModule', path: join(root, 'dist/server/entry.mjs') }];
    for (const directory of ['', 'chunks']) {
      for await (const file of Deno.readDir(join(root, 'dist/server', directory))) {
        if (file.isFile && file.name.endsWith('.mjs') && file.name !== 'entry.mjs') {
          modules.push({ type: 'ESModule', path: join(root, 'dist/server', directory, file.name) });
        }
      }
    }
    const worker = new Miniflare({
      modules, modulesRoot: join(root, 'dist/server'),
      compatibilityDate: '2025-10-02', compatibilityFlags: ['nodejs_compat'],
      d1Databases: { ALTERAN_DB: ':memory:' }, r2Buckets: ['ALTERAN_BLOBS'], bindings,
    });
    try {
      const database = await worker.getD1Database('ALTERAN_DB');
      const migrations = join(root, 'migrations');
      const names: string[] = [];
      for await (const file of Deno.readDir(migrations)) if (file.name.endsWith('.sql')) names.push(file.name);
      for (const name of names.sort()) {
        const statements = (await Deno.readTextFile(join(migrations, name))).split('--> statement-breakpoint');
        for (const sql of statements) if (sql.trim()) await database.prepare(sql.replaceAll('\n', ' ')).run();
      }
      const env = { ...bindings, ALTERAN_DB: database, ALTERAN_BLOBS: await worker.getR2Bucket('ALTERAN_BLOBS') } as unknown as Env;
      const setup = (await import('./fixtures/spaces-worker-context')).default;
      const config = await (await setup.fetch(new Request('https://pds.example/setup?collection-free'), env)).json() as {
        access: string; nonce: string; publicJwk: JWK; privateJwk: JWK;
        space: string; repo: string; collection: string;
      };
      const path = 'https://pds.example/xrpc/com.atproto.space.getRecord';
      const query = new URLSearchParams({ space: config.space, repo: config.repo, collection: config.collection, rkey: 'one' });
      const unauthorized = await worker.dispatchFetch(`${path}?${query}`);
      expect(unauthorized.status).toBe(401);
      expect((await unauthorized.json() as { error: string }).error).toBe('AuthRequired');

      const privateKey = await importJWK(config.privateJwk, 'ES256');
      const proof = await new SignJWT({ htm: 'GET', htu: path, iat: Math.floor(Date.now() / 1000),
        jti: crypto.randomUUID(), nonce: config.nonce, ath: await sha256b64url(config.access) })
        .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: config.publicJwk }).sign(privateKey);
      const response = await worker.dispatchFetch(`${path}?${query}`, {
        headers: { authorization: `DPoP ${config.access}`, dpop: proof, origin: 'https://client.example' },
      });
      expect(response.status).toBe(200);
      expect((await response.json() as { value: unknown }).value).toEqual({ $type: config.collection, text: 'worker context' });
      expect(response.headers.get('cache-control')).toBe('private, no-store');
      expect(response.headers.get('access-control-allow-origin')).toBe('*');
      const head = await worker.dispatchFetch(`${path}?${query}`, { method: 'HEAD' });
      expect(head.status).toBe(405);
      expect(await head.text()).toBe('');
    } finally {
      await worker.dispose();
    }
  },
});
