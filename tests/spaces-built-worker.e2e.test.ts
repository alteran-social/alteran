import { expect } from '@std/expect';
import { Miniflare } from 'miniflare';
import { importJWK, SignJWT, type JWK } from 'jose';
import { join } from 'node:path';
import type { Env } from '../src/env';
import { jwkThumbprint, sha256b64url } from '../src/lib/oauth/dpop';
import { createPersonalSpace } from '../src/db/space-lifecycle-create';
import { applySpaceWrites } from '../src/db/space-store';
import { createOAuthSession } from './helpers/oauth-store';
import { createExplicitSpaceConsent } from '../src/lib/spaces/explicit-read-consent';
import { issueSessionTokens } from '../src/lib/session-tokens';
import { encode } from '@atproto/lex-cbor';
import { sha256 } from '@noble/hashes/sha2.js';
import { CID } from 'multiformats/cid';
import { create as createDigest } from 'multiformats/hashes/digest';
import { readWranglerCompatibility } from './helpers/wrangler-compatibility';

Deno.test({
  name: 'built Astro worker routes authorized private Space reads',
  ignore: Deno.env.get('RUN_APP_TESTS') !== 'true',
  sanitizeOps: false,
  sanitizeResources: false,
  async fn() {
    const root = join(import.meta.dirname!, '..');
    const build = await new Deno.Command(Deno.execPath(), {
      cwd: root, args: ['task', 'build'], stdout: 'piped', stderr: 'piped',
    }).output();
    if (!build.success) throw new Error(`Astro build failed: ${new TextDecoder().decode(build.stderr)}`);
    const compatibility = await readWranglerCompatibility(root);
    const generated: unknown = JSON.parse(await Deno.readTextFile(join(root, 'dist/server/wrangler.json')));
    if (!generated || typeof generated !== 'object' || Array.isArray(generated)) {
      throw new Error('Invalid generated Worker configuration');
    }
    const config = generated as Record<string, unknown>;
    expect(config.compatibility_date).toBe(compatibility.compatibilityDate);
    expect(Array.isArray(config.compatibility_flags) &&
      compatibility.compatibilityFlags.every((flag) => (config.compatibility_flags as unknown[]).includes(flag))).toBe(true);

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
      ...compatibility,
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
      const describe = await worker.dispatchFetch('https://pds.example/xrpc/com.atproto.server.describeServer');
      expect(describe.status).toBe(200);
      const tokenPath = 'https://pds.example/oauth/token';
      for (const origin of [undefined, 'https://pds.example', 'https://client.example']) {
        const tokenProof = await new SignJWT({ htm: 'POST', htu: tokenPath, iat: Math.floor(Date.now() / 1000),
          jti: crypto.randomUUID() })
          .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: config.publicJwk }).sign(privateKey);
        const headers = new Headers({ 'content-type': 'application/x-www-form-urlencoded', dpop: tokenProof });
        if (origin) headers.set('origin', origin);
        const token = await worker.dispatchFetch(tokenPath, { method: 'POST', headers, body: 'grant_type=unsupported' });
        expect(token.status).toBe(400);
        expect((await token.json() as { error: string }).error).toBe('unsupported_grant_type');
      }
      const consentResponse = await worker.dispatchFetch('https://pds.example/oauth/consent', {
        method: 'POST', headers: { origin: 'https://client.example', 'content-type': 'application/x-www-form-urlencoded' },
        body: 'decision=approve',
      });
      expect(consentResponse.status).toBe(403);
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

      const policyPath = 'https://pds.example/xrpc/com.atproto.space.getSpace';
      const policyQuery = new URLSearchParams({ space: config.space });
      const deniedPolicy = await worker.dispatchFetch(`${policyPath}?${policyQuery}`, {
        headers: { origin: 'https://client.example' },
      });
      expect(deniedPolicy.status).toBe(401);
      expect((await deniedPolicy.json() as { error: string }).error).toBe('AuthRequired');
      expect(deniedPolicy.headers.get('cache-control')).toBe('private, no-store');
      expect(deniedPolicy.headers.get('access-control-allow-origin')).toBe('*');
      const policyProof = await new SignJWT({ htm: 'GET', htu: policyPath, iat: Math.floor(Date.now() / 1000),
        jti: crypto.randomUUID(), nonce: config.nonce, ath: await sha256b64url(config.access) })
        .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: config.publicJwk }).sign(privateKey);
      const policy = await worker.dispatchFetch(`${policyPath}?${policyQuery}`, {
        headers: { authorization: `DPoP ${config.access}`, dpop: policyProof, origin: 'https://client.example' },
      });
      expect(policy.status).toBe(200);
      expect(await policy.json()).toEqual({ space: config.space, policy: { $type: 'com.atproto.personalspace.policy' } });
      expect(policy.headers.get('cache-control')).toBe('private, no-store');
      expect(policy.headers.get('access-control-allow-origin')).toBe('*');
      for (const header of ['authorization', 'dpop', 'accept-signature']) {
        expect(headerTokens(policy.headers.get('vary'))).toContain(header);
      }
      const policyReplay = await worker.dispatchFetch(`${policyPath}?${policyQuery}`, {
        headers: { authorization: `DPoP ${config.access}`, dpop: policyProof },
      });
      expect(policyReplay.status).toBe(400);
      expect((await policyReplay.json() as { error: string }).error).toBe('InvalidToken');
      const policyPreflight = await worker.dispatchFetch(policyPath, { method: 'OPTIONS', headers: {
        origin: 'https://client.example', 'access-control-request-method': 'GET',
        'access-control-request-headers': 'authorization,dpop,accept-signature',
      } });
      expect(policyPreflight.status).toBe(204);
      expect(policyPreflight.headers.get('cache-control')).toBe('private, no-store');
      expect(policyPreflight.headers.get('access-control-allow-origin')).toBe('*');
      for (const header of ['authorization', 'dpop', 'accept-signature']) {
        expect(headerTokens(policyPreflight.headers.get('access-control-allow-headers'))).toContain(header);
      }
      const policyHead = await worker.dispatchFetch(`${policyPath}?${policyQuery}`, { method: 'HEAD' });
      expect(policyHead.status).toBe(405);
      expect(await policyHead.text()).toBe('');

      const listPath = 'https://pds.example/xrpc/com.atproto.space.listRecords';
      const account = await database.prepare('SELECT space_incarnation FROM account WHERE did = ?')
        .bind(config.repo).first<{ space_incarnation: string }>();
      if (!account) throw new Error('Missing test account');
      const genesisSpace = `at://${config.repo}/space/com.example.notes/genesis-built`;
      await createPersonalSpace(env, genesisSpace, { $type: 'com.atproto.personalspace.policy' },
        crypto.randomUUID(), account.space_incarnation);
      const clientId = 'https://client.example/metadata';
      const jkt = await jwkThumbprint(config.publicJwk as JsonWebKey);
      const consent = await createExplicitSpaceConsent({ subject: config.repo, accountIncarnation: account.space_incarnation,
        clientId, dpopJkt: jkt, clientAuthMethod: 'none', clientAuthKeyId: null, clientAuthKeyBinding: null,
      }, 'atproto space:com.example.notes?skey=genesis-built&action=read_self');
      if (!consent) throw new Error('Missing genesis consent');
      const sessionId = crypto.randomUUID().replaceAll('-', ''), accessJti = crypto.randomUUID().replaceAll('-', '');
      const genesisTokens = await issueSessionTokens(env, config.repo, { accessScope: consent.tokenScope, clientId, dpopJkt: jkt,
        oauthSessionId: sessionId, accessJti, spaceGrantDigest: consent.digest });
      await createOAuthSession(env, { id: sessionId, did: config.repo, clientId, clientAuthMethod: 'none', dpopJkt: jkt,
        scope: consent.tokenScope, currentRefreshTokenId: genesisTokens.refreshPayload.jti,
        accessJti, expiresAt: genesisTokens.refreshExpiry });
      await database.prepare('INSERT INTO oauth_space_grant (session_id, snapshot, digest, created_at) VALUES (?, ?, ?, unixepoch())')
        .bind(sessionId, consent.serialized, consent.digest).run();
      const genesisQuery = new URLSearchParams({ space: genesisSpace, repo: config.repo, excludeValues: 'true' });
      const genesisProof = await new SignJWT({ htm: 'GET', htu: listPath, iat: Math.floor(Date.now() / 1000),
        jti: crypto.randomUUID(), nonce: config.nonce, ath: await sha256b64url(genesisTokens.accessJwt) })
        .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: config.publicJwk }).sign(privateKey);
      const genesis = await worker.dispatchFetch(`${listPath}?${genesisQuery}`, {
        headers: { authorization: `DPoP ${genesisTokens.accessJwt}`, dpop: genesisProof, origin: 'https://client.example' },
      });
      expect(genesis.status).toBe(200);
      expect(await genesis.json()).toEqual({ records: [] });
      expect(genesis.headers.get('cache-control')).toBe('private, no-store');
      expect(genesis.headers.get('access-control-allow-origin')).toBe('*');
      for (const header of ['authorization', 'dpop', 'accept-signature']) {
        expect(headerTokens(genesis.headers.get('vary'))).toContain(header);
      }
      const replayGenesis = await worker.dispatchFetch(`${listPath}?${genesisQuery}`, {
        headers: { authorization: `DPoP ${genesisTokens.accessJwt}`, dpop: genesisProof },
      });
      expect(replayGenesis.status).toBe(400);
      expect((await replayGenesis.json() as { error: string }).error).toBe('InvalidToken');
      const wrongGenesisProof = await new SignJWT({ htm: 'GET', htu: listPath, iat: Math.floor(Date.now() / 1000),
        jti: crypto.randomUUID(), nonce: config.nonce, ath: await sha256b64url(config.access) })
        .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: config.publicJwk }).sign(privateKey);
      const wrongGenesis = await worker.dispatchFetch(`${listPath}?${genesisQuery}`, {
        headers: { authorization: `DPoP ${config.access}`, dpop: wrongGenesisProof },
      });
      expect(wrongGenesis.status).toBe(401);
      expect((await wrongGenesis.json() as { error: string }).error).toBe('AuthRequired');
      const listQuery = new URLSearchParams({ space: config.space, repo: config.repo, excludeValues: 'true' });
      const wrongActiveProof = await new SignJWT({ htm: 'GET', htu: listPath, iat: Math.floor(Date.now() / 1000),
        jti: crypto.randomUUID(), nonce: config.nonce, ath: await sha256b64url(genesisTokens.accessJwt) })
        .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: config.publicJwk }).sign(privateKey);
      const wrongActive = await worker.dispatchFetch(`${listPath}?${listQuery}`, {
        headers: { authorization: `DPoP ${genesisTokens.accessJwt}`, dpop: wrongActiveProof },
      });
      expect(wrongActive.status).toBe(401);
      expect((await wrongActive.json() as { error: string }).error).toBe('AuthRequired');
      const deniedList = await worker.dispatchFetch(`${listPath}?${listQuery}`, { headers: { origin: 'https://client.example' } });
      expect(deniedList.status).toBe(401);
      expect((await deniedList.json() as { error: string }).error).toBe('AuthRequired');
      expect(deniedList.headers.get('cache-control')).toBe('private, no-store');
      expect(deniedList.headers.get('access-control-allow-origin')).toBe('*');
      const listProof = await new SignJWT({ htm: 'GET', htu: listPath, iat: Math.floor(Date.now() / 1000),
        jti: crypto.randomUUID(), nonce: config.nonce, ath: await sha256b64url(config.access) })
        .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: config.publicJwk }).sign(privateKey);
      const listed = await worker.dispatchFetch(`${listPath}?${listQuery}`, {
        headers: { authorization: `DPoP ${config.access}`, dpop: listProof, origin: 'https://client.example' },
      });
      expect(listed.status).toBe(200);
      const listedBody = await listed.json() as { records: { collection: string; rkey: string; cid: string }[] };
      expect(listedBody.records).toHaveLength(1);
      expect(listedBody.records[0].collection).toBe(config.collection);
      expect(listedBody.records[0].rkey).toBe('one');
      expect(typeof listedBody.records[0].cid).toBe('string');
      expect(Object.keys(listedBody.records[0]).sort()).toEqual(['cid', 'collection', 'rkey']);
      expect(listed.headers.get('cache-control')).toBe('private, no-store');
      expect(listed.headers.get('access-control-allow-origin')).toBe('*');
      for (const header of ['authorization', 'dpop', 'accept-signature']) {
        expect(headerTokens(listed.headers.get('vary'))).toContain(header);
      }

      async function signedList(params: Record<string, string>) {
        const query = new URLSearchParams({ space: config.space, repo: config.repo, ...params });
        const proof = await new SignJWT({ htm: 'GET', htu: listPath, iat: Math.floor(Date.now() / 1000),
          jti: crypto.randomUUID(), nonce: config.nonce, ath: await sha256b64url(config.access) })
          .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: config.publicJwk }).sign(privateKey);
        return worker.dispatchFetch(`${listPath}?${query}`, {
          headers: { authorization: `DPoP ${config.access}`, dpop: proof, origin: 'https://client.example' },
        });
      }
      for (const excludeValues of ['true', 'false']) {
        for (const [cursor, count] of [
          ['', 1], [config.space, 0], ['at://aaa.example/com.example.note/a', 0],
          ['at://zzz.example/com.example.note/a', 1],
          [`${config.space}/${config.repo}/${config.collection}/one`, 0],
          [`${config.space}/${config.repo}/${config.collection}/one#/x%2Fz`, 1],
        ] as const) {
          const response = await signedList({ cursor, excludeValues, collection: config.collection, limit: '1000' });
          expect(response.status).toBe(200);
          const body = await response.json() as { records: { rkey: string }[]; cursor?: string };
          expect(body.records).toHaveLength(count);
          if (count) expect(body.records[0].rkey).toBe('one');
          expect(body.cursor).toBeUndefined();
        }
      }
      const valueQuery = new URLSearchParams({ space: config.space, repo: config.repo });
      const deniedValues = await worker.dispatchFetch(`${listPath}?${valueQuery}`, { headers: { origin: 'https://client.example' } });
      expect(deniedValues.status).toBe(401);
      expect(deniedValues.headers.get('cache-control')).toBe('private, no-store');
      const valueModes: Record<string, string>[] = [{}, { excludeValues: 'false' }];
      for (const params of valueModes) {
        const valuesResponse = await signedList(params);
        expect(valuesResponse.status).toBe(200);
        expect(valuesResponse.headers.get('cache-control')).toBe('private, no-store');
        expect(valuesResponse.headers.get('access-control-allow-origin')).toBe('*');
        const valueBody = await valuesResponse.json() as { records: { value: unknown }[] };
        expect(valueBody.records).toHaveLength(1);
        expect(valueBody.records[0].value).toEqual({ $type: config.collection, text: 'worker context' });
        expect(Object.keys(valueBody.records[0]).sort()).toEqual(['cid', 'collection', 'rkey', 'value']);
      }
      const filtered = await signedList({ collection: config.collection, limit: '1' });
      expect(filtered.status).toBe(200);
      const firstPage = await filtered.json() as { records: { value: unknown }[]; cursor: string };
      expect(firstPage.records).toHaveLength(1);
      expect(firstPage.records[0].value).toEqual({ $type: config.collection, text: 'worker context' });
      expect(firstPage.cursor).toBe(`${config.space}/${config.repo}/${config.collection}/one`);
      const nextPage = await signedList({ collection: config.collection, limit: '1', cursor: firstPage.cursor });
      expect(nextPage.status).toBe(200);
      expect(await nextPage.json()).toEqual({ records: [] });

      const preflight = await worker.dispatchFetch(listPath, { method: 'OPTIONS', headers: {
        origin: 'https://client.example', 'access-control-request-method': 'GET',
        'access-control-request-headers': 'authorization,dpop,accept-signature',
      } });
      expect(preflight.status).toBe(204);
      expect(preflight.headers.get('cache-control')).toBe('private, no-store');
      expect(preflight.headers.get('access-control-allow-origin')).toBe('*');
      for (const header of ['authorization', 'dpop', 'accept-signature']) {
        expect(headerTokens(preflight.headers.get('access-control-allow-headers'))).toContain(header);
      }
      const head = await worker.dispatchFetch(`${path}?${query}`, { method: 'HEAD' });
      expect(head.status).toBe(405);
      expect(await head.text()).toBe('');

      const pageCollection = 'com.example.page';
      await applySpaceWrites(env, config.space, config.repo, Array.from({ length: 51 }, (_, index) => ({
        action: 'create' as const, collection: pageCollection, rkey: `page-${String(index).padStart(3, '0')}`,
        record: { $type: pageCollection, text: `page value ${index}` },
      })), account.space_incarnation);
      for (const excludeValues of ['true', 'false']) {
        for (const limit of ['51', '1000']) {
          const options = { collection: pageCollection, excludeValues, limit };
          const first = await signedList(options);
          expect(first.status).toBe(200);
          const page = await first.json() as { records: { rkey: string; value?: unknown }[]; cursor?: string };
          expect(page.records).toHaveLength(50);
          expect(page.cursor).toBe(`${config.space}/${config.repo}/${pageCollection}/page-001`);
          expect(Object.hasOwn(page.records[0], 'value')).toBe(excludeValues === 'false');
          if (!page.cursor) throw new Error('Missing page cursor');
          const last = await signedList({ ...options, cursor: page.cursor });
          expect(last.status).toBe(200);
          const remainder = await last.json() as { records: { rkey: string }[]; cursor?: string };
          expect(remainder.records).toHaveLength(1);
          expect(remainder.records[0].rkey).toBe('page-000');
          expect(remainder.cursor).toBeUndefined();
        }
      }

      for (const name of ['space_record_fence_update', 'space_record_version_update_guard', 'space_version_fence_update']) {
        await database.prepare(`DROP TRIGGER ${name}`).run();
      }
      const original = { $type: config.collection, n: 9007199254740993n, min: -9223372036854775808n,
        bytes: new Uint8Array([0, 255]), ref: CID.parse('bafkreigh2akiscaildcw453tj2mzyv4eicv7yqmx26iubepzwcndhy6eyu') };
      const input = encode(original as never);
      const cid = CID.createV1(0x71, createDigest(0x12, sha256(input))).toString();
      await database.prepare('UPDATE space_record SET cid = ?, value_cbor = ? WHERE space_ref = ? AND rkey = ?')
        .bind(cid, input, config.space, 'one').run();
      await database.prepare('UPDATE space_record_version SET cid = ?, value_cbor = ?, value_size = ? WHERE space_ref = ? AND rkey = ?')
        .bind(cid, input, input.byteLength, config.space, 'one').run();
      const newProof = await new SignJWT({ htm: 'GET', htu: path, iat: Math.floor(Date.now() / 1000),
        jti: crypto.randomUUID(), nonce: config.nonce, ath: await sha256b64url(config.access) })
        .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: config.publicJwk }).sign(privateKey);
      const exact = await worker.dispatchFetch(`${path}?${query}`, {
        headers: { authorization: `DPoP ${config.access}`, dpop: newProof, origin: 'https://client.example' },
      });
      expect(exact.status).toBe(200);
      const raw = await exact.text();
      expect(raw).toContain('"n":9007199254740993');
      expect(raw).toContain('"min":-9223372036854775808');
      const parsed = JSON.parse(raw) as { value: { bytes: { $bytes: string }; ref: { $link: string } }; cid: string };
      expect(parsed.cid).toBe(cid);
      expect(parsed.value.bytes).toEqual({ $bytes: 'AP8' });
      expect(parsed.value.ref.$link).toBe(original.ref.toString());
      const again = encode({ ...parsed.value, n: 9007199254740993n, min: -9223372036854775808n,
        bytes: new Uint8Array([0, 255]), ref: CID.parse(parsed.value.ref.$link) } as never);
      expect(again.length === input.length && again.every((byte, index) => byte === input[index])).toBe(true);
      const exactList = await signedList({ collection: config.collection });
      expect(exactList.status).toBe(200);
      const listRaw = await exactList.text();
      expect(listRaw).toContain('"n":9007199254740993');
      expect(listRaw).toContain('"min":-9223372036854775808');
      const listParsed = JSON.parse(listRaw) as {
        records: { value: { bytes: { $bytes: string }; ref: { $link: string } }; cid: string }[] };
      expect(listParsed.records).toHaveLength(1);
      expect(listParsed.records[0].cid).toBe(cid);
      expect(listParsed.records[0].value.bytes).toEqual({ $bytes: 'AP8' });
      const fromList = encode({ ...listParsed.records[0].value, n: 9007199254740993n, min: -9223372036854775808n,
        bytes: new Uint8Array([0, 255]), ref: CID.parse(listParsed.records[0].value.ref.$link) } as never);
      expect(fromList.length === input.length && fromList.every((byte, index) => byte === input[index])).toBe(true);
    } finally {
      await worker.dispose();
    }
  },
});

function headerTokens(value: string | null): string[] {
  return (value ?? '').split(',').map((token) => token.trim().toLowerCase()).filter(Boolean);
}
