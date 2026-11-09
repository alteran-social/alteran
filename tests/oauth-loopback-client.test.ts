import { describe, it } from "./helpers/bdd";
import { expect } from "@std/expect";
import { isLoopbackClientId, resolveLoopbackClient } from '../src/lib/oauth/loopback-client';

function metadataFor(clientId: string) {
  const resolution = resolveLoopbackClient(clientId);
  if (resolution.tag !== 'loopback') throw new Error(`expected loopback client, got ${resolution.tag}`);
  return resolution.metadata;
}

describe('loopback development client', () => {
  it('defaults to the atproto scope and the loopback IP redirects', () => {
    const metadata = metadataFor('http://localhost');
    expect(metadata.scope).toBe('atproto');
    expect(metadata.redirect_uris).toEqual(['http://127.0.0.1/', 'http://[::1]/']);
  });

  it('is a native public client that must use DPoP', () => {
    const metadata = metadataFor('http://localhost/');
    expect(metadata.application_type).toBe('native');
    expect(metadata.token_endpoint_auth_method).toBe('none');
    expect(metadata.dpop_bound_access_tokens).toBe(true);
  });

  it('takes its scope and redirect URIs from the client_id query', () => {
    const scope = 'atproto repo:academy.rawkode.tartan.signature?action=create';
    const clientId = `http://localhost?${new URLSearchParams([
      ['redirect_uri', 'http://127.0.0.1/callback'],
      ['redirect_uri', 'http://[::1]/callback'],
      ['scope', scope],
    ])}`;
    const metadata = metadataFor(clientId);
    expect(metadata.client_id).toBe(clientId);
    expect(metadata.scope).toBe(scope);
    expect(metadata.redirect_uris).toEqual(['http://127.0.0.1/callback', 'http://[::1]/callback']);
  });

  it('does not treat other localhost-looking origins as the loopback client', () => {
    for (const clientId of [
      'https://localhost',
      'http://localhost:8080',
      'http://localhost.example.com',
      'http://127.0.0.1',
      'https://client.example/metadata',
    ]) {
      expect(isLoopbackClientId(clientId)).toBe(false);
    }
  });

  it('rejects a client_id with a path', () => {
    expect(resolveLoopbackClient('http://localhost/app').tag).toBe('invalid');
  });

  it('rejects a client_id with a fragment', () => {
    expect(resolveLoopbackClient('http://localhost#frag').tag).toBe('invalid');
  });

  it('rejects unknown query parameters', () => {
    expect(resolveLoopbackClient('http://localhost?client_name=Trusted%20App').tag).toBe('invalid');
  });

  it('rejects a repeated scope parameter', () => {
    expect(resolveLoopbackClient('http://localhost?scope=atproto&scope=atproto').tag).toBe('invalid');
  });

  it('rejects a scope without atproto', () => {
    expect(resolveLoopbackClient('http://localhost?scope=transition%3Ageneric').tag).toBe('invalid');
  });

  it('rejects free text posing as scope values', () => {
    const clientId = `http://localhost?scope=${encodeURIComponent('atproto Official App (verified)')}`;
    expect(resolveLoopbackClient(clientId).tag).toBe('invalid');
  });

  it('rejects redirect URIs that only normalise to a loopback IP', () => {
    for (const redirectUri of ['http://127.1/', 'http://2130706433/', 'http://0x7f.1/callback', 'http://[0:0:0:0:0:0:0:1]/']) {
      const clientId = `http://localhost?redirect_uri=${encodeURIComponent(redirectUri)}`;
      expect(resolveLoopbackClient(clientId).tag).toBe('invalid');
    }
  });

  it('rejects redirect URIs that are not loopback IP literals', () => {
    for (const redirectUri of [
      'http://localhost/callback',
      'https://127.0.0.1/callback',
      'https://client.example/callback',
      'http://127.0.0.1.example.com/callback',
      'http://user@127.0.0.1/callback',
      'com.example.app:/callback',
    ]) {
      const clientId = `http://localhost?redirect_uri=${encodeURIComponent(redirectUri)}`;
      expect(resolveLoopbackClient(clientId).tag).toBe('invalid');
    }
  });
});
