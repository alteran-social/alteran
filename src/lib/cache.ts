// Types via tsconfig.app.json

/**
 * Edge caching utilities for Cloudflare Workers
 *
 * Implements caching strategies for:
 * - DID documents (/.well-known/did.json)
 * - Well-known files (/.well-known/atproto-did)
 * - Frequently-accessed records
 * - Static assets
 */

export interface CacheOptions {
  /**
   * Cache TTL in seconds
   */
  ttl: number;

  /**
   * Cache key prefix
   */
  prefix?: string;

  /**
   * Whether to use stale-while-revalidate
   */
  swr?: boolean;

  /**
   * Stale-while-revalidate duration in seconds
   */
  swrTtl?: number;
}

/**
 * Default cache configurations for different content types
 */
export const CACHE_CONFIGS = {
  // DID documents rarely change
  DID_DOCUMENT: {
    ttl: 3600, // 1 hour
    swr: true,
    swrTtl: 86400, // 24 hours
  },

  // Well-known files are static
  WELL_KNOWN: {
    ttl: 3600, // 1 hour
    swr: true,
    swrTtl: 86400, // 24 hours
  },

  // Records can be cached briefly
  RECORD: {
    ttl: 60, // 1 minute
    swr: true,
    swrTtl: 300, // 5 minutes
  },

  // Repo snapshots can be cached
  REPO_SNAPSHOT: {
    ttl: 300, // 5 minutes
    swr: true,
    swrTtl: 3600, // 1 hour
  },
} as const;

/**
 * Generate cache headers for a response
 */
export function getCacheHeaders(options: CacheOptions): Record<string, string> {
  const headers: Record<string, string> = {};

  if (options.swr && options.swrTtl) {
    // Use stale-while-revalidate
    headers['Cache-Control'] = `public, max-age=${options.ttl}, stale-while-revalidate=${options.swrTtl}`;
  } else {
    // Simple max-age
    headers['Cache-Control'] = `public, max-age=${options.ttl}`;
  }

  // Add ETag for conditional requests
  headers['Vary'] = 'Accept, Accept-Encoding';

  return headers;
}

/**
 * Create a cache key from request
 */
export function getCacheKey(request: Request, prefix?: string): string {
  const url = new URL(request.url);
  const key = `${url.pathname}${url.search}`;
  return prefix ? `${prefix}:${key}` : key;
}

/**
 * Get cached response from Cache API
 */
function resolveDefaultCache(): Cache | null {
  if (typeof caches === 'undefined') {
    return null;
  }
  try {
    return ((caches as any).default ?? null) as Cache | null;
  } catch {
    return null;
  }
}

export async function getCachedResponse(
  request: Request,
  options?: { prefix?: string }
): Promise<Response | null> {
  try {
    const cache = resolveDefaultCache();
    if (!cache) {
      return null;
    }
    const cacheKey = getCacheKey(request, options?.prefix);
    const cacheUrl = new URL(cacheKey, request.url);
    const cacheRequest = new Request(cacheUrl, request);

    return (await cache.match(cacheRequest)) ?? null;
  } catch (error) {
    console.error('Cache read error:', error);
    return null;
  }
}

/**
 * Put response in cache
 */
export async function putCachedResponse(
  request: Request,
  response: Response,
  options: CacheOptions
): Promise<void> {
  try {
    const cache = resolveDefaultCache();
    if (!cache) {
      return;
    }
    const cacheKey = getCacheKey(request, options.prefix);
    const cacheUrl = new URL(cacheKey, request.url);
    const cacheRequest = new Request(cacheUrl, request);

    // Clone response and add cache headers
    const headers = new Headers(response.headers);
    const cacheHeaders = getCacheHeaders(options);
    for (const [key, value] of Object.entries(cacheHeaders)) {
      headers.set(key, value);
    }

    const cachedResponse = new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers,
    });

    await cache.put(cacheRequest, cachedResponse);
  } catch (error) {
    console.error('Cache write error:', error);
  }
}

/**
 * Invalidate cache entry
 */
export async function invalidateCache(
  request: Request,
  options?: { prefix?: string }
): Promise<boolean> {
  try {
    const cache = resolveDefaultCache();
    if (!cache) {
      return false;
    }
    const cacheKey = getCacheKey(request, options?.prefix);
    const cacheUrl = new URL(cacheKey, request.url);
    const cacheRequest = new Request(cacheUrl, request);

    return await cache.delete(cacheRequest);
  } catch (error) {
    console.error('Cache invalidation error:', error);
    return false;
  }
}

/**
 * Middleware to handle caching for GET requests
 */
export async function withCache(
  request: Request,
  handler: () => Promise<Response>,
  options: CacheOptions
): Promise<Response> {
  // Only cache GET requests
  if (request.method !== 'GET') {
    return handler();
  }

  // Check cache first
  const cached = await getCachedResponse(request, { prefix: options.prefix });
  if (cached) {
    // Clone the cached response to avoid immutable headers issue
    // Cache API responses have immutable headers which Astro may try to modify
    return new Response(cached.body, {
      status: cached.status,
      statusText: cached.statusText,
      headers: new Headers(cached.headers),
    });
  }

  // Generate response
  const response = await handler();

  // Only cache successful responses
  if (response.ok) {
    // Don't await - cache in background
    putCachedResponse(request, response.clone(), options);
  }

  return response;
}

/**
 * Generate ETag from content
 */
export async function generateETag(content: string | Uint8Array): Promise<string> {
  const data = typeof content === 'string'
    ? new TextEncoder().encode(content)
    : content;

  // Digest accepts a BufferSource, so pass the Uint8Array view directly
  const hash = await crypto.subtle.digest('SHA-256', new Uint8Array(data));
  const hashArray = Array.from(new Uint8Array(hash));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

  return `"${hashHex.substring(0, 16)}"`;
}

/**
 * Check if request has matching ETag
 */
export function checkETag(request: Request, etag: string): boolean {
  const ifNoneMatch = request.headers.get('If-None-Match');
  return ifNoneMatch === etag;
}

/**
 * Create 304 Not Modified response
 */
export function notModifiedResponse(etag: string): Response {
  return new Response(null, {
    status: 304,
    headers: {
      'ETag': etag,
      'Cache-Control': 'public, max-age=3600',
    },
  });
}
