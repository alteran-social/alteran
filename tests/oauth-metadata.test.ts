import { describe, expect, it } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';
import { makeEnv } from './helpers/env';
import { GET as authServerMetadata } from '../src/pages/.well-known/oauth-authorization-server';
import { GET as protectedResourceMetadata } from '../src/pages/.well-known/oauth-protected-resource';
import { GET as jwks } from '../src/pages/oauth/jwks';

describe('OAuth metadata and route injection', () => {
  it('advertises atproto OAuth server metadata with PAR, JWKS, and revocation', async () => {
    const env = await makeEnv();
    const request = new Request('https://pds.example/.well-known/oauth-authorization-server');
    const res = await authServerMetadata({ locals: { runtime: { env } }, request } as any);
    const body = await res.json() as any;
    expect(body.issuer).toBe('https://pds.example');
    expect(body.pushed_authorization_request_endpoint).toBe('https://pds.example/oauth/par');
    expect(body.jwks_uri).toBe('https://pds.example/oauth/jwks');
    expect(body.revocation_endpoint).toBe('https://pds.example/oauth/revoke');
    expect(body.scopes_supported).toContain('atproto');
    expect(body.require_pushed_authorization_requests).toBe(true);
    expect(body.dpop_signing_alg_values_supported).toEqual(['ES256']);
  });

  it('advertises protected-resource metadata', async () => {
    const env = await makeEnv();
    const request = new Request('https://pds.example/.well-known/oauth-protected-resource');
    const res = await protectedResourceMetadata({ locals: { runtime: { env } }, request } as any);
    const body = await res.json() as any;
    expect(body.resource).toBe('https://pds.example');
    expect(body.authorization_servers).toEqual(['https://pds.example']);
    expect(body.bearer_methods_supported).toEqual(['header']);
  });

  it('uses configured public PDS hostname instead of reflecting alternate request hosts', async () => {
    const env = await makeEnv({ PDS_HOSTNAME: 'canonical.example' });

    const authRes = await authServerMetadata({
      locals: { runtime: { env } },
      request: new Request('https://worker-preview.example/.well-known/oauth-authorization-server'),
    } as any);
    const authBody = await authRes.json() as any;
    expect(authBody.issuer).toBe('https://canonical.example');
    expect(authBody.token_endpoint).toBe('https://canonical.example/oauth/token');
    expect(authBody.protected_resources).toEqual(['https://canonical.example']);

    const resourceRes = await protectedResourceMetadata({
      locals: { runtime: { env } },
      request: new Request('https://worker-preview.example/.well-known/oauth-protected-resource'),
    } as any);
    const resourceBody = await resourceRes.json() as any;
    expect(resourceBody.resource).toBe('https://canonical.example');
    expect(resourceBody.authorization_servers).toEqual(['https://canonical.example']);
  });

  it('serves a public AS JWKS without exposing symmetric session secrets', async () => {
    const env = await makeEnv();
    const res = await jwks({ locals: { runtime: { env } } } as any);
    const body = await res.json() as any;
    expect(body.keys).toHaveLength(1);
    expect(body.keys[0].kty).toBe('EC');
    expect(body.keys[0].d).toBeUndefined();
    expect(body.keys[0].alg).toBe('ES256');
  });

  it('injects OAuth routes from the packaged integration', () => {
    const integration = readFileSync(join(process.cwd(), 'index.js'), 'utf8');
    for (const route of [
      '/.well-known/oauth-authorization-server',
      '/.well-known/oauth-protected-resource',
      '/oauth/par',
      '/oauth/authorize',
      '/oauth/consent',
      '/oauth/token',
      '/oauth/jwks',
      '/oauth/revoke',
    ]) {
      expect(integration).toContain(`pattern: '${route}'`);
    }
  });
});
