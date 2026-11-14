import { expect } from '@std/expect';
import { Miniflare } from 'miniflare';
import { importJWK, SignJWT, type JWK } from 'jose';
import { join } from 'node:path';
import type { Env } from '../src/env';
import { jwkThumbprint, sha256b64url } from '../src/lib/oauth/dpop';
import { createOAuthSession } from './helpers/oauth-store';
import { createExplicitSpaceConsent } from '../src/lib/spaces/explicit-read-consent';
import { issueSessionTokens } from '../src/lib/session-tokens';
import { readWranglerCompatibility } from './helpers/wrangler-compatibility';

async function copyTree(source: string, destination: string): Promise<void> {
  await Deno.mkdir(destination, { recursive: true });
  for await (const entry of Deno.readDir(source)) {
    const from = join(source, entry.name), to = join(destination, entry.name);
    if (entry.isDirectory) await copyTree(from, to);
    else if (entry.isFile) await Deno.copyFile(from, to);
    else throw new Error('Unexpected package entry');
  }
}

Deno.test({
  name: 'an external Astro consumer serves injected owner Space listing',
  ignore: Deno.env.get('RUN_APP_TESTS') !== 'true', sanitizeOps: false, sanitizeResources: false,
  async fn() {
    const root = join(import.meta.dirname!, '..');
    const consumer = await Deno.makeTempDir({ prefix: 'alteran-spaces-consumer-' });
    let worker: Miniflare | undefined;
    try {
      const compatibility = await readWranglerCompatibility(root);
      await Deno.mkdir(join(consumer, 'src/pages'), { recursive: true });
      await Deno.mkdir(join(consumer, 'node_modules/@alteran-social/astro'), { recursive: true });
      for await (const entry of Deno.readDir(join(root, 'node_modules'))) {
        if (entry.name === '@alteran-social' || entry.name === '.vite') continue;
        await Deno.symlink(join(root, 'node_modules', entry.name), join(consumer, 'node_modules', entry.name));
      }
      const installedPackage = join(consumer, 'node_modules/@alteran-social/astro');
      for (const directory of ['src', 'types', 'migrations']) await copyTree(join(root, directory), join(installedPackage, directory));
      for (const name of ['package.json', 'index.js', 'index.d.ts']) await Deno.copyFile(join(root, name), join(installedPackage, name));
      await Deno.writeTextFile(join(consumer, 'package.json'), JSON.stringify({ name: 'alteran-test-consumer', private: true,
        type: 'module', dependencies: { '@alteran-social/astro': `file:${installedPackage}`,
          astro: '6.3.3', '@astrojs/cloudflare': '13.5.1' } }));
      await Deno.writeTextFile(join(consumer, 'astro.config.mjs'), `import { defineConfig } from 'astro/config';
import cloudflare from '@astrojs/cloudflare';
import alteran from '@alteran-social/astro';
export default defineConfig({ output: 'server', adapter: cloudflare({ mode: 'advanced', imageService: 'custom' }),
  integrations: [alteran()] });\n`);
      await Deno.writeTextFile(join(consumer, 'src/pages/index.astro'), '<h1>External consumer</h1>\n');
      await Deno.writeTextFile(join(consumer, 'wrangler.jsonc'), JSON.stringify({ name: 'alteran-test-consumer',
        main: 'node_modules/@alteran-social/astro/src/_worker.ts', compatibility_date: compatibility.compatibilityDate,
        compatibility_flags: compatibility.compatibilityFlags }));
      const build = await new Deno.Command(Deno.execPath(), { cwd: consumer, stdout: 'piped', stderr: 'piped',
        args: ['run', '-A', '--config', join(root, 'deno.json'), 'npm:astro', 'build', '--root', consumer] }).output();
      if (!build.success) throw new Error(`External Astro build failed: ${new TextDecoder().decode(build.stderr)}`);
      const server = join(consumer, 'dist/server');
      const modules: { type: 'ESModule'; path: string }[] = [{ type: 'ESModule', path: join(server, 'entry.mjs') }];
      for (const directory of ['', 'chunks']) {
        for await (const file of Deno.readDir(join(server, directory))) {
          if (file.isFile && file.name.endsWith('.mjs') && file.name !== 'entry.mjs') {
            modules.push({ type: 'ESModule', path: join(server, directory, file.name) });
          }
        }
      }
      const bindings = { PDS_DID: 'did:example:test', PDS_HANDLE: 'test.example', USER_PASSWORD: 'pwd',
        ACCESS_TOKEN: 'test-only-access-secret', REFRESH_TOKEN: 'test-only-refresh-secret',
        REFRESH_TOKEN_SECRET: 'test-only-refresh-secret', SESSION_JWT_SECRET: 'test-only-session-secret', PDS_RELAY_NOTIFY: 'false' };
      worker = new Miniflare({ modules, modulesRoot: server, compatibilityDate: compatibility.compatibilityDate,
        compatibilityFlags: compatibility.compatibilityFlags, d1Databases: { ALTERAN_DB: ':memory:' },
        r2Buckets: ['ALTERAN_BLOBS'], bindings });
      const database = await worker.getD1Database('ALTERAN_DB');
      const migrations = join(root, 'migrations'), names: string[] = [];
      for await (const file of Deno.readDir(migrations)) if (file.name.endsWith('.sql')) names.push(file.name);
      for (const name of names.sort()) {
        for (const sql of (await Deno.readTextFile(join(migrations, name))).split('--> statement-breakpoint')) {
          if (sql.trim()) await database.prepare(sql.replaceAll('\n', ' ')).run();
        }
      }
      const env = { ...bindings, ALTERAN_DB: database, ALTERAN_BLOBS: await worker.getR2Bucket('ALTERAN_BLOBS') } as unknown as Env;
      const setup = (await import('./fixtures/spaces-worker-context')).default;
      const config = await (await setup.fetch(new Request('https://pds.example/setup?collection-free'), env)).json() as {
        nonce: string; publicJwk: JWK; privateJwk: JWK; space: string; repo: string;
      };
      const account = await database.prepare('SELECT space_incarnation FROM account WHERE did = ?')
        .bind(config.repo).first<{ space_incarnation: string }>();
      if (!account) throw new Error('Missing test account');
      const clientId = 'https://client.example/metadata', jkt = await jwkThumbprint(config.publicJwk as JsonWebKey);
      const consent = await createExplicitSpaceConsent({ subject: config.repo, accountIncarnation: account.space_incarnation,
        clientId, dpopJkt: jkt, clientAuthMethod: 'none', clientAuthKeyId: null, clientAuthKeyBinding: null },
        'atproto space:com.example.notes?skey=*&action=read_self');
      if (!consent) throw new Error('Missing listing consent');
      const sessionId = crypto.randomUUID().replaceAll('-', ''), accessJti = crypto.randomUUID().replaceAll('-', '');
      const tokens = await issueSessionTokens(env, config.repo, { accessScope: consent.tokenScope, clientId, dpopJkt: jkt,
        oauthSessionId: sessionId, accessJti, spaceGrantDigest: consent.digest });
      await createOAuthSession(env, { id: sessionId, did: config.repo, clientId, clientAuthMethod: 'none', dpopJkt: jkt,
        scope: consent.tokenScope, currentRefreshTokenId: tokens.refreshPayload.jti, accessJti, expiresAt: tokens.refreshExpiry });
      await database.prepare('INSERT INTO oauth_space_grant (session_id, snapshot, digest, created_at) VALUES (?, ?, ?, unixepoch())')
        .bind(sessionId, consent.serialized, consent.digest).run();
      const path = 'https://pds.example/xrpc/com.atproto.space.listSpaces';
      const proof = await new SignJWT({ htm: 'GET', htu: path, iat: Math.floor(Date.now() / 1000), jti: crypto.randomUUID(),
        nonce: config.nonce, ath: await sha256b64url(tokens.accessJwt) })
        .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: config.publicJwk })
        .sign(await importJWK(config.privateJwk, 'ES256'));
      const query = new URLSearchParams({ spaceDid: config.repo, spaceType: 'com.example.notes' });
      const response = await worker.dispatchFetch(`${path}?${query}`, { headers: {
        authorization: `DPoP ${tokens.accessJwt}`, dpop: proof, origin: 'https://client.example',
      } });
      expect(response.status).toBe(200);
      expect(response.headers.get('cache-control')).toBe('private, no-store');
      const body = await response.json() as { spaces: { space: string; repoRev?: string; data?: { $bytes: string } }[] };
      expect(body.spaces).toHaveLength(1);
      expect(body.spaces[0].space).toBe(config.space);
      expect(typeof body.spaces[0].repoRev).toBe('string');
      expect(typeof body.spaces[0].data?.$bytes).toBe('string');
    } finally {
      await worker?.dispose();
      await Deno.remove(consumer, { recursive: true });
    }
  },
});
