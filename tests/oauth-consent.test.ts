import { describe, it } from "./helpers/bdd";
import { expect } from "@std/expect";
import { makeEnv } from './helpers/env';
import { mockClientMetadata } from './helpers/oauth';
import { loadPar, savePar, consumeCode, saveCode } from '../src/lib/oauth/store';
import { checkConsentPasswordLockout, reserveConsentPasswordAttempt } from '../src/lib/oauth/consent';
import { GET as authorize } from '../src/pages/oauth/authorize';
import { GET as consentGet, POST as consentPost } from '../src/pages/oauth/consent';

const clientId = 'https://client.example/metadata';
const requestUri = 'urn:ietf:params:oauth:request_uri:req123';

async function seedPar(env: any, id = 'req123', overrides: Record<string, unknown> = {}) {
  await savePar(env, id, {
    client_id: clientId,
    redirect_uri: 'https://client.example/callback',
    code_challenge: 'challenge',
    code_challenge_method: 'S256',
    scope: 'atproto',
    state: 'state123',
    dpopJkt: 'jkt123',
    clientAuthMethod: 'none',
    clientAuthKeyId: null,
    createdAt: Math.floor(Date.now() / 1000),
    expiresAt: Math.floor(Date.now() / 1000) + 300,
    ...overrides,
  });
}

async function consentCsrf(env: any, id: string) {
  const uri = `urn:ietf:params:oauth:request_uri:${id}`;
  const getRes = await consentGet({ locals: { runtime: { env } }, request: new Request(`https://pds.example/oauth/consent?request_uri=${encodeURIComponent(uri)}`) } as any);
  return {
    status: getRes.status,
    location: getRes.headers.get('location'),
    csrf: (await getRes.text()).match(/name="csrf" value="([^"]+)"/)?.[1] ?? '',
    uri,
  };
}

describe('OAuth single-user consent', () => {
  it('does not issue a code from authorize and fails prompt=none without auth', async () => {
    const env = await makeEnv();
    await seedPar(env);
    const res = await authorize({ locals: { runtime: { env } }, request: new Request(`https://pds.example/oauth/authorize?client_id=${encodeURIComponent(clientId)}&request_uri=${encodeURIComponent(requestUri)}&prompt=none`) } as any);
    expect(res.status).toBe(302);
    const redirect = new URL(res.headers.get('location') ?? '');
    expect(redirect.searchParams.get('error')).toBe('login_required');
    expect(redirect.searchParams.get('state')).toBe('state123');
    expect(await loadPar(env, 'req123')).toBeNull();
  });

  it('honors prompt=none from the pushed authorization request', async () => {
    const env = await makeEnv();
    await seedPar(env, 'req123', { prompt: 'none' });
    const res = await authorize({ locals: { runtime: { env } }, request: new Request(`https://pds.example/oauth/authorize?client_id=${encodeURIComponent(clientId)}&request_uri=${encodeURIComponent(requestUri)}`) } as any);
    expect(res.status).toBe(302);
    const redirect = new URL(res.headers.get('location') ?? '');
    expect(redirect.searchParams.get('error')).toBe('login_required');
    expect(await loadPar(env, 'req123')).toBeNull();
  });

  it('does not let direct consent bypass login_hint checks', async () => {
    const restore = mockClientMetadata(clientId);
    try {
      const env = await makeEnv();
      await seedPar(env, 'req123', { login_hint: 'did:example:other' });
      const get = await consentCsrf(env, 'req123');
      expect(get.status).toBe(302);
      expect(new URL(get.location ?? '').searchParams.get('error')).toBe('login_required');
      expect(await loadPar(env, 'req123')).toBeNull();
    } finally {
      restore();
    }
  });

  it('requires same-origin CSRF and password before issuing a code', async () => {
    const restore = mockClientMetadata(clientId);
    try {
      const env = await makeEnv();
      await seedPar(env);
      const { csrf } = await consentCsrf(env, 'req123');
      expect(csrf.length).toBeGreaterThan(8);

      const bad = await consentPost({
        locals: { runtime: { env } },
        request: new Request('https://pds.example/oauth/consent', {
          method: 'POST',
          headers: { origin: 'https://evil.example', 'content-type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ request_uri: requestUri, client_id: clientId, csrf, decision: 'allow', password: 'pwd' }).toString(),
        }),
      } as any);
      expect(bad.status).toBe(403);

      const ok = await consentPost({
        locals: { runtime: { env } },
        request: new Request('https://pds.example/oauth/consent', {
          method: 'POST',
          headers: { origin: 'https://pds.example', 'content-type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ request_uri: requestUri, client_id: clientId, csrf, decision: 'allow', password: 'pwd' }).toString(),
        }),
      } as any);
      expect(ok.status).toBe(302);
      const redirect = new URL(ok.headers.get('location') ?? '');
      const code = redirect.searchParams.get('code') ?? '';
      expect(code.length).toBeGreaterThan(8);
      expect(redirect.searchParams.get('state')).toBe('state123');
      expect(await loadPar(env, 'req123')).toBeNull();
      const codeRec = await consumeCode(env, code);
      expect(codeRec?.did).toBe('did:example:test');
      expect(codeRec?.client_id).toBe(clientId);
    } finally {
      restore();
    }
  });

  it('consumes rejected requests', async () => {
    const restore = mockClientMetadata(clientId);
    try {
      const env = await makeEnv();
      await seedPar(env);
      const { csrf } = await consentCsrf(env, 'req123');
      const denied = await consentPost({
        locals: { runtime: { env } },
        request: new Request('https://pds.example/oauth/consent', {
          method: 'POST',
          headers: { origin: 'https://pds.example', 'content-type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ request_uri: requestUri, client_id: clientId, csrf, decision: 'deny' }).toString(),
        }),
      } as any);
      expect(denied.status).toBe(302);
      expect(new URL(denied.headers.get('location') ?? '').searchParams.get('error')).toBe('access_denied');
      expect(await loadPar(env, 'req123')).toBeNull();
    } finally {
      restore();
    }
  });

  it('renders deny without password constraint validation', async () => {
    const restore = mockClientMetadata(clientId);
    try {
      const env = await makeEnv();
      await seedPar(env);
      const res = await consentGet({ locals: { runtime: { env } }, request: new Request(`https://pds.example/oauth/consent?request_uri=${encodeURIComponent(requestUri)}`) } as any);
      const html = await res.text();
      expect(html).toContain('name="password" type="password" autocomplete="current-password" required');
      expect(html).toContain('name="decision" value="deny" type="submit" formnovalidate');
    } finally {
      restore();
    }
  });

  it('uses configured public PDS hostname for front-channel issuer', async () => {
    const env = await makeEnv({ PDS_HOSTNAME: 'canonical.example' });
    await seedPar(env);
    const { csrf } = await consentCsrf(env, 'req123');
    const denied = await consentPost({
      locals: { runtime: { env } },
      request: new Request('https://worker-preview.example/oauth/consent', {
        method: 'POST',
        headers: { origin: 'https://worker-preview.example', 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ request_uri: requestUri, client_id: clientId, csrf, decision: 'deny' }).toString(),
      }),
    } as any);
    expect(denied.status).toBe(302);
    const redirect = new URL(denied.headers.get('location') ?? '');
    expect(redirect.searchParams.get('iss')).toBe('https://canonical.example');
  });

  it('locks out repeated failed password attempts', async () => {
    const restore = mockClientMetadata(clientId);
    try {
      const env = await makeEnv();
      for (let i = 0; i < 4; i++) {
        const id = `bad${i}`;
        await seedPar(env, id);
        const { csrf, uri } = await consentCsrf(env, id);
        const bad = await consentPost({
          locals: { runtime: { env } },
          request: new Request('https://pds.example/oauth/consent', {
            method: 'POST',
            headers: { origin: 'https://pds.example', 'content-type': 'application/x-www-form-urlencoded', 'cf-connecting-ip': '203.0.113.10' },
            body: new URLSearchParams({ request_uri: uri, client_id: clientId, csrf, decision: 'allow', password: 'wrong' }).toString(),
          }),
        } as any);
        expect(bad.status).toBe(302);
      }

      await seedPar(env, 'locked');
      const { csrf, uri } = await consentCsrf(env, 'locked');
      const locked = await consentPost({
        locals: { runtime: { env } },
        request: new Request('https://pds.example/oauth/consent', {
          method: 'POST',
          headers: { origin: 'https://pds.example', 'content-type': 'application/x-www-form-urlencoded', 'cf-connecting-ip': '203.0.113.10' },
          body: new URLSearchParams({ request_uri: uri, client_id: clientId, csrf, decision: 'allow', password: 'pwd' }).toString(),
        }),
      } as any);
      expect(locked.status).toBe(429);
    } finally {
      restore();
    }
  });

  it('atomically records concurrent failed password attempts', async () => {
    const env = await makeEnv();
    const request = new Request('https://pds.example/oauth/consent', {
      headers: { 'cf-connecting-ip': '198.51.100.25' },
    });
    const results = await Promise.all(Array.from({ length: 5 }, () => reserveConsentPasswordAttempt(env, request)));

    const row = await env.ALTERAN_DB.prepare(
      'SELECT attempts, locked_until FROM login_attempts WHERE ip = ?'
    ).bind('198.51.100.25').first<{ attempts: number; locked_until: number | null }>();
    expect(row?.attempts).toBe(5);
    expect(row?.locked_until ?? 0).toBeGreaterThan(Math.floor(Date.now() / 1000));
    expect(results.filter((result) => result?.status === 429)).toHaveLength(1);
    expect((await checkConsentPasswordLockout(env, request))?.status).toBe(429);
  });

  it('atomically consumes authorization codes once', async () => {
    const env = await makeEnv();
    const code = 'code-race';
    await saveCode(env, code, {
      code,
      client_id: clientId,
      redirect_uri: 'https://client.example/callback',
      code_challenge: 'challenge',
      scope: 'atproto',
      dpopJkt: 'jkt123',
      clientAuthMethod: 'none',
      clientAuthKeyId: null,
      did: 'did:example:test',
      createdAt: Math.floor(Date.now() / 1000),
      expiresAt: Math.floor(Date.now() / 1000) + 300,
    });
    const attempts = await Promise.all(Array.from({ length: 20 }, () => consumeCode(env, code)));
    expect(attempts.filter(Boolean)).toHaveLength(1);
  });
});
