import { expect } from '@std/expect';
import { isCanonicalJwksGet, isPrivateProtocolPath, privateProtocolMethod } from '../src/lib/private-protocol-path';

Deno.test('middleware identifies private Space and OAuth paths after routing normalization', () => {
  for (const path of [
    '/xrpc/com.atproto.space.getRecord', '/xrpc/com.atproto.space.createSpace',
    '/xrpc/com.atproto.personalspace.get', '/xrpc/com.atproto.memberspace.listMembers',
    '/xrpc/com.atproto.managedspace.get', '/xrpc/com%2eatproto.space.getRecord',
    '/xr%70c/com.atproto.space.getRecord', '/xrpc%2fcom.atproto.space.getRecord',
    '/xr%2570c/com.atproto.space.getRecord', '/xr%zzpc/com.atproto.space.getRecord',
    '//xrpc/com.atproto.space.getRecord', '/pds/xrpc/com.atproto.space.getRecord',
    '/pds/xrpc/other/xrpc/com.atproto.space.getRecord', '/%58rpc/com.atproto.space.getRecord',
    '/x%52pc/com.atproto.space.getRecord', '/pds/xrpc/com.atproto.space.getRecord/private-path-secret',
    '/oauth/par', '/oauth/token', '/pds/oauth/consent', '/%6fauth/par', '//oauth/token',
    '/oauth/jwks', '/pds/oauth/%6aw%6bs',
    '/oauth%5ctoken', '/xrpc%5ccom.atproto.space.getRecord',
    '/xrpc//com.atproto.space.getRecord', '/xrpc/%2Fcom.atproto.space.getRecord',
    '/pds/xrpc///com.atproto.memberspace.listMembers',
    '/xrpc/foo%5c..%5ccom.atproto.space.getRecord', '/oauth/foo%2f..%2ftoken',
    '/xrpc%2fcom.atproto.space.getRecord%2f..%2f..%2fpublic/private-path-secret',
    '/xrpc//%252e%252e/com.atproto.space.getRecord', '/xrpc/com%2Eatproto.repo.getRecord',
    '/%78%72%70%63//%2e%2e/com.atproto.space.getRecord',
  ]) expect(isPrivateProtocolPath(path)).toBe(true);
  for (const path of ['/xrpc/com.atproto.repo.getRecord',
    '/pds/xrpc/com.atproto.repo.getRecord', '/assets/a%20b.png', '/spaces']) {
    expect(isPrivateProtocolPath(path)).toBe(false);
  }
  expect(isCanonicalJwksGet(new Request('https://pds.example/oauth/jwks'))).toBe(true);
  expect(isCanonicalJwksGet(new Request('https://pds.example/pds/oauth/jwks'))).toBe(false);
  expect(isCanonicalJwksGet(new Request('https://pds.example/oauth/jwks?value=1'))).toBe(false);
  expect(isCanonicalJwksGet(new Request('https://pds.example/oauth/jwks?'))).toBe(false);
  expect(isCanonicalJwksGet(new Request('https://pds.example/oauth/%6aw%6bs'))).toBe(false);
  expect(isCanonicalJwksGet(new Request('https://pds.example/oauth/jwks', { method: 'POST' }))).toBe(false);
  expect(isCanonicalJwksGet(new Request('https://pds.example/xrpc/com.atproto.space.getRecord/oauth/jwks'))).toBe(false);
  expect(isCanonicalJwksGet(new Request('https://pds.example/oauth/par/oauth/jwks'))).toBe(false);
  expect(privateProtocolMethod('PRIVATE-SKEY-MARKER')).toBe('other');
  expect(privateProtocolMethod('GET')).toBe('GET');
});
