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

Deno.test('Space list requests are bounded, cursor-bound and default to values', () => {
  const parsed = parseSpaceListRequest(request(base));
  expect(parsed.tag).toBe('valid');
  if (parsed.tag !== 'valid') throw new Error('Missing valid request');
  expect(parsed.target.limit).toBe(50);
  expect(parsed.target.excludeValues).toBe(true);
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
  expect(next.target.cursorPath).toBe('com.example.note/one');
  for (const entries of [
    [...base, ['excludeValues', 'true']],
    [['space', space], ['repo', repo], ['excludeValues', '1']],
    [...base, ['unknown', 'x']],
    [...base, ['limit', '51']],
    [...base, ['limit', '01']],
    [...base, ['collection', 'bad']],
  ] as [string, string][][]) expect(parseSpaceListRequest(request(entries)).tag).toBe('invalid');
  for (const cursorValue of [`${space}/did:example:other/com.example.note/one`, `${cursor}/extra`, 'not-a-cursor']) {
    expect(parseSpaceListRequest(request([...base, ['cursor', cursorValue]]))).toEqual({ tag: 'invalid', error: 'InvalidCursor' });
  }
});
