import { describe, it, beforeEach } from "./helpers/bdd";
import { expect } from "@std/expect";
import { __testHooks } from '../src/lib/appview/did-resolver';

describe('didDocumentCache', () => {
  beforeEach(() => {
    __testHooks.reset();
  });

  it('evicts the oldest entry when size cap is exceeded', async () => {
    __testHooks.setFetcher(async (did) => ({ id: did }));
    for (let i = 0; i < 1100; i++) {
      await __testHooks.resolve(`did:web:host-${i}.example`);
    }
    expect(__testHooks.cacheSize()).toBeLessThanOrEqual(1024);
  });

  it('refetches entries past the TTL', async () => {
    let now = 0;
    __testHooks.setClock(() => now);

    let fetchCount = 0;
    __testHooks.setFetcher(async (did) => {
      fetchCount += 1;
      return { id: did };
    });

    await __testHooks.resolve('did:web:a.example');
    expect(fetchCount).toBe(1);

    // Same key, still fresh — should hit the cache.
    await __testHooks.resolve('did:web:a.example');
    expect(fetchCount).toBe(1);

    // Advance past 10 minutes.
    now = 11 * 60 * 1000;
    await __testHooks.resolve('did:web:a.example');
    expect(fetchCount).toBe(2);
  });

  it('caches successful fetches within the TTL window', async () => {
    let fetchCount = 0;
    __testHooks.setFetcher(async (did) => {
      fetchCount += 1;
      return { id: did };
    });

    await __testHooks.resolve('did:web:a.example');
    await __testHooks.resolve('did:web:a.example');
    await __testHooks.resolve('did:web:a.example');
    expect(fetchCount).toBe(1);
  });

  it('evicts failed lookups so they are retried', async () => {
    let attempts = 0;
    __testHooks.setFetcher(async () => {
      attempts += 1;
      throw new Error('boom');
    });

    await expect(__testHooks.resolve('did:web:a.example')).rejects.toThrow('boom');
    await expect(__testHooks.resolve('did:web:a.example')).rejects.toThrow('boom');
    expect(attempts).toBe(2);
    expect(__testHooks.cacheSize()).toBe(0);
  });
});
