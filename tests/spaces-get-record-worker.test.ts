import { expect } from '@std/expect';
import { Miniflare } from 'miniflare';
import { importJWK, SignJWT, type JWK } from 'jose';
import { join } from 'node:path';
import { sha256b64url } from '../src/lib/oauth/dpop';

Deno.test({
  name: 'Space getRecord passes through the workerd middleware and preserves CORS headers',
  sanitizeOps: false,
  sanitizeResources: false,
  async fn() {
    const root = join(import.meta.dirname!, '..');
    const temp = await Deno.makeTempDir({ prefix: 'alteran-spaces-route-' });
    const stub = join(temp, 'astro-env.js'), bundle = join(temp, 'worker.mjs');
    await Deno.writeTextFile(stub, 'export function getSecret() { return undefined; }\n');
    const build = await new Deno.Command(Deno.execPath(), {
      cwd: root,
      args: ['run', '-A', 'npm:esbuild@0.25.12', 'tests/fixtures/spaces-get-record-worker.ts',
        '--bundle', '--format=esm', '--platform=browser', '--external:node:*', '--external:cloudflare:workers',
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
      for (const headers of [{}, { origin: 'https://client.example' }]) {
        const signal = await worker.dispatchFetch('https://pds.example/synthetic-abort', { headers });
        expect(await signal.json()).toEqual({ original: true, normalized: true });
      }
      const config = await (await worker.dispatchFetch('https://pds.example/setup')).json() as {
        access: string; nonce: string; publicJwk: JWK; privateJwk: JWK;
        space: string; repo: string; collection: string;
      };
      const privateKey = await importJWK(config.privateJwk, 'ES256');
      const ath = await sha256b64url(config.access);
      const path = 'https://pds.example/xrpc/com.atproto.space.getRecord';
      const query = new URLSearchParams({ space: config.space, repo: config.repo, collection: config.collection, rkey: 'one' });
      const proof = await new SignJWT({ htm: 'GET', htu: path, iat: Math.floor(Date.now() / 1000),
        jti: crypto.randomUUID(), nonce: config.nonce, ath })
        .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: config.publicJwk }).sign(privateKey);
      const response = await worker.dispatchFetch(`${path}?${query}`, {
        headers: { authorization: `DPoP ${config.access}`, dpop: proof, origin: 'https://client.example' },
      });
      expect(response.status).toBe(200);
      expect((await response.json() as { value: unknown }).value).toEqual({ $type: config.collection, text: 'worker context' });
      checkPrivateCors(response);
      const listPath = 'https://pds.example/xrpc/com.atproto.space.listRecords';
      const listQuery = new URLSearchParams({ space: config.space, repo: config.repo, excludeValues: 'true' });
      const listProof = await new SignJWT({ htm: 'GET', htu: listPath, iat: Math.floor(Date.now() / 1000),
        jti: crypto.randomUUID(), nonce: config.nonce, ath })
        .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: config.publicJwk }).sign(privateKey);
      const listed = await worker.dispatchFetch(`${listPath}?${listQuery}`, {
        headers: { authorization: `DPoP ${config.access}`, dpop: listProof, origin: 'https://client.example' },
      });
      expect(listed.status).toBe(200);
      const listBody = await listed.json() as { records: { collection: string; rkey: string; cid: string }[] };
      expect(listBody.records).toHaveLength(1);
      expect(listBody.records[0].collection).toBe(config.collection);
      expect(listBody.records[0].rkey).toBe('one');
      expect(Object.keys(listBody.records[0]).sort()).toEqual(['cid', 'collection', 'rkey']);
      checkPrivateCors(listed);
      const valueQuery = new URLSearchParams({ space: config.space, repo: config.repo });
      const valueProof = await new SignJWT({ htm: 'GET', htu: listPath, iat: Math.floor(Date.now() / 1000),
        jti: crypto.randomUUID(), nonce: config.nonce, ath })
        .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: config.publicJwk }).sign(privateKey);
      const values = await worker.dispatchFetch(`${listPath}?${valueQuery}`, {
        headers: { authorization: `DPoP ${config.access}`, dpop: valueProof, origin: 'https://client.example' },
      });
      expect(values.status).toBe(200);
      const valueBody = await values.json() as { records: { value: unknown }[] };
      expect(valueBody.records).toHaveLength(1);
      expect(valueBody.records[0].value).toEqual({ $type: config.collection, text: 'worker context' });
      checkPrivateCors(values);
      const bad = await worker.dispatchFetch(`${path}?${query}`, {
        headers: { authorization: `DPoP ${config.access}`, dpop: 'bad', origin: 'https://client.example' },
      });
      expect(bad.status).toBe(401);
      expect(bad.headers.get('dpop-nonce')).toBeTruthy();
      expect(bad.headers.get('access-control-expose-headers')?.toLowerCase()).toContain('dpop-nonce');
      expect(bad.headers.get('access-control-expose-headers')?.toLowerCase()).toContain('www-authenticate');
      checkPrivateCors(bad);
      const head = await worker.dispatchFetch(`${path}?${query}`, { method: 'HEAD' });
      expect(head.status).toBe(405);
      expect(await head.text()).toBe('');
      checkPrivateCors(head);
      const merged = await worker.dispatchFetch(path, { headers: { 'x-test-mode': 'merge' } });
      expect(merged.status).toBe(404);
      const exposed = (merged.headers.get('access-control-expose-headers') ?? '').toLowerCase().split(',').map((x) => x.trim());
      expect(exposed).toEqual(['x-existing', 'dpop-nonce']);
      expect(merged.headers.get('vary')?.toLowerCase()).toContain('origin');
      checkPrivateCors(merged);
      const wildcard = await worker.dispatchFetch(path, { headers: { 'x-test-mode': 'wildcard' } });
      expect(wildcard.headers.get('vary')).toBe('*');
      expect(wildcard.headers.get('access-control-expose-headers')).toBe('*, DPoP-Nonce');
      const thrown = await worker.dispatchFetch(path, { headers: { 'x-test-mode': 'throw' } });
      expect(thrown.status).toBe(500);
      expect(await thrown.text()).not.toContain('secret middleware failure');
      expect(thrown.headers.get('x-test-sensitive-log')).toBe('false');
      checkPrivateCors(thrown);
      for (const target of [
        '/xrpc/com.atproto.space.createSpace', '/xrpc/com.atproto.memberspace.listMembers',
        '/xrpc/com.atproto.personalspace.get', '/xrpc/com.atproto.managedspace.get',
        '/xrpc/com%2eatproto.space.getRecord', '/xr%70c/com.atproto.space.getRecord',
        '//xrpc/com.atproto.space.getRecord', '/pds/xrpc/com.atproto.space.getRecord/private-path-secret',
        '/oauth/par', '/pds/oauth/token/private-path-secret',
      ]) {
        const failure = await worker.dispatchFetch(`https://pds.example${target}`, { headers: { 'x-test-mode': 'throw' } });
        expect(failure.status).toBe(500);
        expect(await failure.text()).not.toContain('secret middleware failure');
        expect(failure.headers.get('x-test-sensitive-log')).toBe('false');
        expect(failure.headers.get('x-test-path-log')).toBe('false');
        expect(failure.headers.get('x-test-path-metric')).toBe('false');
        checkPrivateCors(failure);
      }
      const publicFailure = await worker.dispatchFetch('https://pds.example/xrpc/com.atproto.repo.getRecord', {
        headers: { 'x-test-mode': 'throw' },
      });
      expect(await publicFailure.text()).toContain('secret middleware failure');
      expect(publicFailure.headers.get('x-test-sensitive-log')).toBe('true');
      const jwks = await worker.dispatchFetch('https://pds.example/oauth/jwks', { headers: { 'x-test-mode': 'jwks-cache' } });
      expect(jwks.headers.get('cache-control')).toBe('public, max-age=300');
      const basedJwks = await worker.dispatchFetch('https://pds.example/pds/oauth/jwks', { headers: { 'x-test-mode': 'jwks-cache' } });
      expect(basedJwks.headers.get('cache-control')).toBe('private, no-store');
      const queriedJwks = await worker.dispatchFetch('https://pds.example/oauth/jwks?value=1', {
        headers: { 'x-test-mode': 'jwks-cache' },
      });
      expect(queriedJwks.headers.get('cache-control')).toBe('private, no-store');
      const disguisedJwks = await worker.dispatchFetch('https://pds.example/xrpc/com.atproto.space.getRecord/oauth/jwks', {
        headers: { 'x-test-mode': 'jwks-cache' },
      });
      expect(disguisedJwks.headers.get('cache-control')).toBe('private, no-store');
      await db.prepare(`INSERT INTO secret (key, value, updated_at) VALUES (?, ?, unixepoch())
        ON CONFLICT (key) DO UPDATE SET value = excluded.value`).bind('oauth:as:signing-key', 'KEYSECRET__invalid_json').run();
      const malformedJwks = await worker.dispatchFetch('https://pds.example/oauth/jwks', { headers: { 'x-test-mode': 'jwks-real' } });
      expect(malformedJwks.status).toBe(500);
      expect(await malformedJwks.text()).not.toContain('KEYSECRET');
      expect(malformedJwks.headers.get('x-test-sensitive-log')).toBe('false');
      expect(malformedJwks.headers.get('cache-control')).toBe('private, no-store');
      await db.prepare('DELETE FROM secret WHERE key = ?').bind('oauth:as:signing-key').run();
      const actualJwks = await worker.dispatchFetch('https://pds.example/oauth/jwks', { headers: { 'x-test-mode': 'jwks-real' } });
      expect(actualJwks.status).toBe(200);
      expect(actualJwks.headers.get('cache-control')).toBe('public, max-age=300');
      for (const target of ['/oauth/par', '/xrpc/com.atproto.space.getRecord']) {
        const failure = await worker.dispatchFetch(`https://pds.example${target}`, { headers: { 'x-test-mode': 'returned-500' } });
        expect(failure.status).toBe(500);
        expect(await failure.text()).not.toContain('secret middleware failure');
        expect(failure.headers.get('x-private')).toBeNull();
        expect(failure.headers.get('vary')).toBe('*');
      }
      const preflight = await worker.dispatchFetch(path, { method: 'OPTIONS', headers: {
        origin: 'https://client.example', 'access-control-request-method': 'GET',
        'access-control-request-headers': 'authorization,dpop,accept-signature',
      } });
      expect(preflight.status).toBe(204);
      expect(preflight.headers.get('access-control-allow-origin')).toBe('*');
      expect(preflight.headers.get('cache-control')).toBe('private, no-store');
      const allowed = preflight.headers.get('access-control-allow-headers')?.toLowerCase().split(',').map((x) => x.trim()) ?? [];
      for (const header of ['authorization', 'dpop', 'accept-signature']) expect(allowed).toContain(header);
    } finally {
      await worker.dispose();
      await Deno.remove(temp, { recursive: true });
    }
  },
});

function checkPrivateCors(response: Response) {
  expect(response.headers.get('cache-control')).toBe('private, no-store');
  expect(response.headers.get('access-control-allow-origin')).toBe('*');
  const vary = (response.headers.get('vary') ?? '').toLowerCase();
  for (const name of ['accept-signature', 'authorization', 'dpop']) expect(vary).toContain(name);
}
