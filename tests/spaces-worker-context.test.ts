import { expect } from '@std/expect';
import { Miniflare } from 'miniflare';
import { importJWK, SignJWT, type JWK } from 'jose';
import { join } from 'node:path';
import { sha256b64url } from '../src/lib/oauth/dpop';

Deno.test({
  name: 'Space principal stays bound to the actual workerd request and D1 binding',
  sanitizeOps: false,
  sanitizeResources: false,
  async fn() {
    const root = join(import.meta.dirname!, '..');
    const temp = await Deno.makeTempDir({ prefix: 'alteran-spaces-worker-' });
    const stub = join(temp, 'astro-env.js'), bundle = join(temp, 'worker.mjs');
    await Deno.writeTextFile(stub, 'export function getSecret() { return undefined; }\n');
    const build = await new Deno.Command(Deno.execPath(), {
      cwd: root,
      args: ['run', '-A', 'npm:esbuild@0.25.12', 'tests/fixtures/spaces-worker-context.ts',
        '--bundle', '--format=esm', '--platform=browser', '--external:node:*',
        `--alias:astro:env/server=${stub}`, `--outfile=${bundle}`],
      stdout: 'piped', stderr: 'piped',
    }).output();
    if (!build.success) throw new Error(`Test Worker bundle failed: ${new TextDecoder().decode(build.stderr)}`);
    const worker = new Miniflare({
      modules: true, scriptPath: bundle, modulesRoot: temp, compatibilityDate: '2025-10-02',
      compatibilityFlags: ['nodejs_compat'], d1Databases: { ALTERAN_DB: ':memory:' },
      bindings: { PDS_DID: 'did:example:test', PDS_HANDLE: 'test.example', SESSION_JWT_SECRET: 'test-only-session-secret' },
    });
    try {
      const db = await worker.getD1Database('ALTERAN_DB');
      const dir = join(root, 'migrations');
      const names: string[] = [];
      for await (const file of Deno.readDir(dir)) if (file.name.endsWith('.sql')) names.push(file.name);
      for (const name of names.sort()) {
        for (const sql of (await Deno.readTextFile(join(dir, name))).split('--> statement-breakpoint')) {
          if (sql.trim()) await db.prepare(sql.replaceAll('\n', ' ')).run();
        }
      }
      const setup = await worker.dispatchFetch('https://pds.example/setup');
      expect(setup.status).toBe(200);
      const config = await setup.json() as { access: string; nonce: string; publicJwk: JWK; privateJwk: JWK;
        space: string; repo: string; collection: string };
      const privateKey = await importJWK(config.privateJwk, 'ES256');
      const ath = await sha256b64url(config.access);
      const target = 'https://pds.example/xrpc/com.atproto.space.getRecord';
      const params = new URLSearchParams({ space: config.space, repo: config.repo, collection: config.collection, rkey: 'one' });
      const proof = () => new SignJWT({ htm: 'GET', htu: target, iat: Math.floor(Date.now() / 1000),
        jti: crypto.randomUUID(), nonce: config.nonce, ath })
        .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: config.publicJwk }).sign(privateKey);
      async function get(query: string, signed: string) {
        return worker.dispatchFetch(`${target}?${query}`, {
          headers: { authorization: `DPoP ${config.access}`, dpop: signed },
        });
      }
      const clonedProof = await proof();
      const cloned = await get(`${params}&clone=1`, clonedProof);
      expect(cloned.status).toBe(200);
      expect((await cloned.json() as { tag: string }).tag).toBe('unauthorized');
      expect((await get(params.toString(), clonedProof)).status).toBe(401);
      const valid = await get(params.toString(), await proof());
      expect(valid.status).toBe(200);
      expect((await valid.json() as { tag: string }).tag).toBe('found');
    } finally {
      await worker.dispose();
      await Deno.remove(temp, { recursive: true });
    }
  },
});
