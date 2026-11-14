import { expect } from '@std/expect';
import { securePrivateProtocolResponse } from '../src/lib/private-protocol-response';

Deno.test('private Worker responses retain security headers and sanitize server errors', async () => {
  const challenge = securePrivateProtocolResponse(new Response('denied', { status: 401, headers: {
    vary: 'Origin', 'www-authenticate': 'DPoP', 'dpop-nonce': 'example-nonce',
    'access-control-expose-headers': 'X-Existing',
  } }));
  expect(challenge.status).toBe(401);
  expect(await challenge.text()).toBe('denied');
  expect(challenge.headers.get('cache-control')).toBe('private, no-store');
  expect(challenge.headers.get('access-control-allow-origin')).toBe('*');
  expect(challenge.headers.get('vary')?.toLowerCase()).toContain('origin');
  const exposed = challenge.headers.get('access-control-expose-headers')?.toLowerCase() ?? '';
  expect(exposed).toContain('x-existing');
  expect(exposed).toContain('dpop-nonce');
  expect(exposed).toContain('www-authenticate');

  let cancelled = false;
  const stream = new ReadableStream({ cancel() { cancelled = true; } });
  const failure = securePrivateProtocolResponse(new Response(stream, { status: 503, headers: {
    vary: '*', 'retry-after': '12345678', 'set-cookie': 'private-cookie', 'x-private': 'sensitive-header',
  } }));
  await Promise.resolve();
  expect(cancelled).toBe(true);
  expect(failure.status).toBe(503);
  expect(await failure.text()).not.toContain('sensitive');
  expect(failure.headers.get('x-private')).toBeNull();
  expect(failure.headers.get('set-cookie')).toBeNull();
  expect(failure.headers.get('vary')).toBe('*');
  expect(failure.headers.get('retry-after')).toBeNull();
  expect(failure.headers.get('cache-control')).toBe('private, no-store');
});
