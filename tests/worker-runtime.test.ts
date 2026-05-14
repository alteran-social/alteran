import { describe, it } from "./helpers/bdd";
import { expect } from "@std/expect";
import { normalizePdsRequestForAstro, normalizeXrpcRequestForAstro } from '../src/worker/runtime';

describe('normalizeXrpcRequestForAstro', () => {
  it('leaves non-XRPC requests unchanged', () => {
    const request = new Request('https://rawkode.dev/health', { method: 'POST' });

    expect(normalizeXrpcRequestForAstro(request as any) as unknown).toBe(request);
  });

  it('adds a same-origin Origin header to bodyless XRPC POSTs', () => {
    const request = new Request('https://rawkode.dev/xrpc/com.atproto.server.refreshSession', {
      method: 'POST',
    });

    const normalized = normalizeXrpcRequestForAstro(request as any) as unknown as Request;

    expect(normalized.headers.get('origin')).toBe('https://rawkode.dev');
    expect(normalized.method).toBe('POST');
  });

  it('overrides cross-origin Origin only for XRPC requests', () => {
    const request = new Request('https://rawkode.dev/xrpc/com.atproto.server.refreshSession', {
      method: 'POST',
      headers: { origin: 'https://bsky.app' },
    });

    const normalized = normalizeXrpcRequestForAstro(request as any) as unknown as Request;

    expect(normalized.headers.get('origin')).toBe('https://rawkode.dev');
  });

  it('preserves XRPC request bodies while normalizing Origin', async () => {
    const request = new Request('https://rawkode.dev/xrpc/com.atproto.repo.createRecord', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{"collection":"app.bsky.feed.post"}',
    });

    const normalized = normalizeXrpcRequestForAstro(request as any) as unknown as Request;

    expect(normalized.headers.get('origin')).toBe('https://rawkode.dev');
    expect(await normalized.text()).toBe('{"collection":"app.bsky.feed.post"}');
  });

  it('normalizes OAuth backchannel POST origins for Astro', async () => {
    const request = new Request('https://rawkode.dev/oauth/par', {
      method: 'POST',
      headers: {
        origin: 'https://client.example',
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: 'client_id=https%3A%2F%2Fclient.example%2Fmetadata',
    });

    const normalized = normalizePdsRequestForAstro(request as any) as unknown as Request;

    expect(normalized.headers.get('origin')).toBe('https://rawkode.dev');
    expect(await normalized.text()).toBe('client_id=https%3A%2F%2Fclient.example%2Fmetadata');
  });

  it('does not normalize OAuth consent POST origins', () => {
    const request = new Request('https://rawkode.dev/oauth/consent', {
      method: 'POST',
      headers: { origin: 'https://client.example' },
    });

    expect(normalizePdsRequestForAstro(request as any) as unknown).toBe(request);
  });

  it('keeps the legacy XRPC normalization export working', () => {
    const request = new Request('https://rawkode.dev/oauth/token', { method: 'POST' });

    const normalized = normalizeXrpcRequestForAstro(request as any) as unknown as Request;

    expect(normalized.headers.get('origin')).toBe('https://rawkode.dev');
  });
});
