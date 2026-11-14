import { expect } from '@std/expect';
import { parseSpaceListRequest } from '../src/lib/spaces/list-records-request';
import { captureRecordIdentity } from '../src/lib/spaces/record-response-input';

const space = 'at://did:example:test/space/com.example.notes/room';
const repo = 'did:example:test';
const endpoint = 'https://pds.example/xrpc/com.atproto.space.listRecords';
function request(entries: [string, string][]) {
  return new Request(`${endpoint}?${new URLSearchParams(entries)}`);
}
const base: [string, string][] = [['space', space], ['repo', repo], ['excludeValues', 'true']];

Deno.test('Space list requests are bounded and default to values', () => {
  const parsed = parseSpaceListRequest(request(base));
  expect(parsed.tag).toBe('valid');
  if (parsed.tag !== 'valid') throw new Error('Missing valid request');
  expect(parsed.target.limit).toBe(50);
  expect(parsed.target.excludeValues).toBe(true);
  expect(parsed.target.cursor).toEqual({ tag: 'unbounded' });
  for (const entries of [[['space', space], ['repo', repo]],
    [['space', space], ['repo', repo], ['excludeValues', 'false']]] as [string, string][][]) {
    const withValues = parseSpaceListRequest(request(entries));
    if (withValues.tag !== 'valid') throw new Error('Expected value-bearing request');
    expect(withValues.target.excludeValues).toBe(false);
  }
  const cursor = captureRecordIdentity({ space, repo, collection: 'com.example.note', rkey: 'one' }).uri;
  const next = parseSpaceListRequest(request([...base, ['limit', '2'], ['cursor', cursor]]));
  expect(next.tag).toBe('valid');
  if (next.tag !== 'valid') throw new Error('Missing valid cursor');
  expect(next.target.cursor).toEqual({ tag: 'before', path: 'com.example.note/one' });
  for (const limit of ['1', '49', '50', '51', '99', '100', '999', '1000']) {
    const value = parseSpaceListRequest(request([...base, ['limit', limit]]));
    expect(value.tag).toBe('valid');
    if (value.tag !== 'valid') throw new Error('Missing valid request');
    expect(value.target.limit).toBe(Number(limit));
  }
  for (const entries of [
    [...base, ['excludeValues', 'true']],
    [['space', space], ['repo', repo], ['excludeValues', '1']],
    [...base, ['unknown', 'x']],
    ...['0', '1001', '10000', '-1', '+1', '1.0', '1e2', '', ' 1', '01']
      .map((limit): [string, string][] => [...base, ['limit', limit]]),
    [...base, ['limit', '1'], ['limit', '2']],
    [...base, ['collection', 'bad']],
  ] as [string, string][][]) expect(parseSpaceListRequest(request(entries)).tag).toBe('invalid');
  for (const cursorValue of [`${cursor}/extra`, `${cursor}/`, `${cursor}?x=1`, `${cursor}#/bad%GG`, 'not-a-cursor']) {
    expect(parseSpaceListRequest(request([...base, ['cursor', cursorValue]]))).toEqual({ tag: 'invalid', error: 'InvalidCursor' });
  }
});

Deno.test('Space list cursors retain literal reference URI ordering', () => {
  const prefix = `${space}/${repo}/`;
  const cases = [
    ['', { tag: 'unbounded' }],
    [space, { tag: 'empty' }],
    ['at://aaa.example/com.example.note/a', { tag: 'empty' }],
    ['at://zzz.example/com.example.note/a', { tag: 'unbounded' }],
    ['at://did:example:%GG/com.example.note/a', { tag: 'empty' }],
    [`${space}/did:example:aaa/com.example.note/one`, { tag: 'empty' }],
    [`${space}/did:example:zzz/com.example.note/one`, { tag: 'unbounded' }],
    [`at://${repo}/space/com.example.notes/aaa/${repo}/com.example.note/one`, { tag: 'empty' }],
    [`at://${repo}/space/com.example.notes/zzz/${repo}/com.example.note/one`, { tag: 'unbounded' }],
    [`${prefix}com.example.note/one`, { tag: 'before', path: 'com.example.note/one' }],
    [`${prefix}com.example.note/one#/x%2Fz`, { tag: 'before', path: 'com.example.note/one#/x%2Fz' }],
    [`${prefix}com.example.note/one#/x%2fz`, { tag: 'before', path: 'com.example.note/one#/x%2fz' }],
  ] as const;
  for (const [cursor, expected] of cases) {
    const result = parseSpaceListRequest(request([...base, ['cursor', cursor]]));
    expect(result.tag).toBe('valid');
    if (result.tag !== 'valid') throw new Error('Missing cursor range');
    expect(result.target.cursor).toEqual(expected);
  }
  const escapedSpace = 'at://did:example:%4A/space/com.example.notes/room';
  const escapedRepo = 'did:example:%4A';
  const escaped = `at://did:example:%4a/space/com.example.notes/room/${escapedRepo}/com.example.note/one`;
  const result = parseSpaceListRequest(request([['space', escapedSpace], ['repo', escapedRepo], ['cursor', escaped]]));
  expect(result.tag).toBe('valid');
  if (result.tag !== 'valid') throw new Error('Missing escaped cursor');
  expect(result.target.cursor).toEqual({ tag: 'unbounded' });
});

Deno.test('Space list cursor and request URL lengths follow their separate limits', () => {
  const prefix = 'at://did:example:x/com.example.note/a#/';
  const atLimit = prefix + 'a'.repeat(8192 - prefix.length);
  expect(parseSpaceListRequest(request([...base, ['cursor', atLimit]])).tag).toBe('valid');
  expect(parseSpaceListRequest(request([...base, ['cursor', `${atLimit}a`]])))
    .toEqual({ tag: 'invalid', error: 'InvalidCursor' });
  const overUrl = request([...base, ['cursor', `${prefix}${'/'.repeat(8000)}`]]);
  expect(overUrl.url.length).toBeGreaterThan(16_384);
  expect(parseSpaceListRequest(overUrl)).toEqual({ tag: 'invalid', error: 'InvalidRequest' });
});
