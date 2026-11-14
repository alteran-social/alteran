import { expect } from '@std/expect';
import { Miniflare } from 'miniflare';
import { importJWK, SignJWT, type JWK } from 'jose';
import { join } from 'node:path';
import type { Env } from '../src/env';
import { jwkThumbprint, sha256b64url } from '../src/lib/oauth/dpop';
import { createPersonalSpace } from '../src/db/space-lifecycle-create';
import { createOAuthSession } from './helpers/oauth-store';
import { createExplicitSpaceConsent } from '../src/lib/spaces/explicit-read-consent';
import { issueSessionTokens } from '../src/lib/session-tokens';
import { readWranglerCompatibility } from './helpers/wrangler-compatibility';

Deno.test({
  name: 'built Astro worker routes restricted owner Space listings',
  ignore: Deno.env.get('RUN_APP_TESTS') !== 'true', sanitizeOps: false, sanitizeResources: false,
  async fn() {
    const root = join(import.meta.dirname!, '..');
    const compatibility = await readWranglerCompatibility(root);
    const build = await new Deno.Command(Deno.execPath(), {
      cwd: root, args: ['task', 'build'], stdout: 'piped', stderr: 'piped',
    }).output();
    if (!build.success) throw new Error(`Astro build failed: ${new TextDecoder().decode(build.stderr)}`);
    const bindings = { PDS_DID: 'did:example:test', PDS_HANDLE: 'test.example', USER_PASSWORD: 'pwd',
      SESSION_JWT_SECRET: 'test-only-session-secret', PDS_RELAY_NOTIFY: 'false' };
    const modules: { type: 'ESModule'; path: string }[] = [{ type: 'ESModule', path: join(root, 'dist/server/entry.mjs') }];
    for (const directory of ['', 'chunks']) {
      for await (const file of Deno.readDir(join(root, 'dist/server', directory))) {
        if (file.isFile && file.name.endsWith('.mjs') && file.name !== 'entry.mjs') {
          modules.push({ type: 'ESModule', path: join(root, 'dist/server', directory, file.name) });
        }
      }
    }
    const worker = new Miniflare({ modules, modulesRoot: join(root, 'dist/server'),
      compatibilityDate: compatibility.compatibilityDate, compatibilityFlags: compatibility.compatibilityFlags,
      d1Databases: { ALTERAN_DB: ':memory:' }, r2Buckets: ['ALTERAN_BLOBS'], bindings });
    try {
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
        access: string; nonce: string; publicJwk: JWK; privateJwk: JWK; space: string; repo: string;
      };
      const account = await database.prepare('SELECT space_incarnation FROM account WHERE did = ?')
        .bind(config.repo).first<{ space_incarnation: string }>();
      if (!account) throw new Error('Missing test account');
      const empty = `at://${config.repo}/space/com.example.notes/empty-built`;
      await createPersonalSpace(env, empty, { $type: 'com.atproto.personalspace.policy' }, crypto.randomUUID(), account.space_incarnation);
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
      const privateKey = await importJWK(config.privateJwk, 'ES256');
      async function signed(access: string) {
        return new SignJWT({ htm: 'GET', htu: path, iat: Math.floor(Date.now() / 1000), jti: crypto.randomUUID(),
          nonce: config.nonce, ath: await sha256b64url(access) })
          .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: config.publicJwk }).sign(privateKey);
      }
      const query = new URLSearchParams({ spaceDid: config.repo, spaceType: 'com.example.notes', limit: '1' });
      const proof = await signed(tokens.accessJwt);
      const first = await worker.dispatchFetch(`${path}?${query}`, { headers: {
        authorization: `DPoP ${tokens.accessJwt}`, dpop: proof, origin: 'https://client.example',
      } });
      expect(first.status).toBe(200);
      expect(first.headers.get('cache-control')).toBe('private, no-store');
      expect(first.headers.get('access-control-allow-origin')).toBe('*');
      const page = await first.json() as { spaces: { space: string }[]; cursor: string };
      expect(page.spaces).toEqual([{ space: empty }]);
      expect(page.cursor).toBe(empty);
      query.set('cursor', page.cursor);
      const second = await worker.dispatchFetch(`${path}?${query}`, { headers: {
        authorization: `DPoP ${tokens.accessJwt}`, dpop: await signed(tokens.accessJwt), origin: 'https://client.example',
      } });
      expect(second.status).toBe(200);
      const secondPage = await second.json() as { spaces: { space: string; repoRev: string; data: { $bytes: string } }[] };
      expect(secondPage.spaces).toHaveLength(1);
      expect(secondPage.spaces[0].space).toBe(config.space);
      expect(typeof secondPage.spaces[0].repoRev).toBe('string');
      expect(typeof secondPage.spaces[0].data.$bytes).toBe('string');
      for (const [cursor, expected] of [
        ['', empty], [empty + '#/part%2Fvalue', config.space],
        ['at://did:zzz:other/space/com.example.other/end', null],
      ] as [string, string | null][]) {
        query.set('cursor', cursor);
        const response = await worker.dispatchFetch(`${path}?${query}`, { headers: {
          authorization: `DPoP ${tokens.accessJwt}`, dpop: await signed(tokens.accessJwt),
        } });
        expect(response.status).toBe(200);
        const result = await response.json() as { spaces: { space: string }[]; cursor?: string };
        expect(result.spaces.map((entry) => entry.space)).toEqual(expected ? [expected] : []);
        expect(result.cursor).toBe(expected ?? undefined);
      }
      const replay = await worker.dispatchFetch(`${path}?${query}`, { headers: {
        authorization: `DPoP ${tokens.accessJwt}`, dpop: proof,
      } });
      expect(replay.status).toBe(400);
      expect((await replay.json() as { error: string }).error).toBe('InvalidToken');
      const narrow = await worker.dispatchFetch(`${path}?${query}`, { headers: {
        authorization: `DPoP ${config.access}`, dpop: await signed(config.access),
      } });
      expect(narrow.status).toBe(403);
      const preflight = await worker.dispatchFetch(path, { method: 'OPTIONS', headers: {
        origin: 'https://client.example', 'access-control-request-method': 'GET',
        'access-control-request-headers': 'authorization,dpop',
      } });
      expect(preflight.status).toBe(204);
      expect(preflight.headers.get('cache-control')).toBe('private, no-store');
    } finally { await worker.dispose(); }
  },
});
