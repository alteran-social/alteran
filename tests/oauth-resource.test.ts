import { describe, it, expect } from 'bun:test';
import { ResourceAuthError, verifyResourceRequestHybrid } from '../src/lib/oauth/resource';

describe('verifyResourceRequestHybrid', () => {
  it('propagates expired bearer tokens as errors', async () => {
    const req = new Request('https://example.com/xrpc/com.atproto.repo.createRecord', {
      headers: { authorization: 'Bearer stale-token' },
    });

    const deps = {
      verifyAccessToken: async () => {
        throw new ResourceAuthError('expired_token');
      },
    } as any;

    await expect(verifyResourceRequestHybrid({} as any, req, deps)).rejects.toMatchObject({ code: 'expired_token' });
  });

  it('returns did/token when bearer verification succeeds', async () => {
    const req = new Request('https://example.com/xrpc/com.atproto.repo.createRecord', {
      headers: { authorization: 'Bearer good-token' },
    });

    const deps = {
      verifyAccessToken: async () => ({ sub: 'did:example:1234' }),
    } as any;

    const result = await verifyResourceRequestHybrid({} as any, req, deps);
    expect(result).toEqual({ did: 'did:example:1234', token: 'good-token' });
  });
});
