import { expect } from '@std/expect';
import { parseListSpacesRequest } from '../src/lib/spaces/list-spaces-request';

const endpoint = 'https://pds.example/xrpc/com.atproto.space.listSpaces';
const did = 'did:example:test', type = 'com.example.notes';
const base: [string, string][] = [['spaceDid', did], ['spaceType', type]];
const request = (entries: [string, string][]) => new Request(`${endpoint}?${new URLSearchParams(entries)}`);

Deno.test('Space listing requires bounded authority and type filters with literal reference cursors', () => {
  const parsed = parseListSpacesRequest(request(base));
  expect(parsed.tag).toBe('valid');
  if (parsed.tag !== 'valid') throw new Error('Missing target');
  expect(parsed.target).toEqual({ authorityDid: did, spaceType: type, limit: 50, cursor: null });
  for (const limit of ['1', '50', '100']) {
    const result = parseListSpacesRequest(request([...base, ['limit', limit]]));
    expect(result.tag).toBe('valid');
  }
  for (const entries of [[], [['spaceDid', did]], [['spaceType', type]], [...base, ['limit', '0']],
    [...base, ['limit', '101']], [...base, ['limit', '01']], [...base, ['limit', '1.0']],
    [...base, ['limit', '1'], ['limit', '2']], [...base, ['unknown', 'x']],
    [['spaceDid', 'invalid'], ['spaceType', type]], [['spaceDid', did], ['spaceType', 'invalid']],
  ] as [string, string][][]) expect(parseListSpacesRequest(request(entries))).toEqual({ tag: 'invalid', error: 'InvalidRequest' });
  const cursor = `at://${did}/space/${type}/one`;
  for (const value of ['', cursor, `at://did:example:other/space/${type}/one`,
    `at://${did}/space/com.example.other/one`, `${cursor}#/path%2Fsegment`,
    `${cursor}#/${'a'.repeat(8192 - cursor.length - 2)}`]) {
    const next = parseListSpacesRequest(request([...base, ['cursor', value]]));
    expect(next.tag).toBe('valid');
    if (next.tag !== 'valid') throw new Error('Missing cursor');
    expect(next.target.cursor).toBe(value || null);
  }
  for (const value of ['not-a-cursor', `${cursor}/extra`, `${cursor}?query`, `${cursor}#invalid`,
    `${cursor}#/%FF`, `${cursor}#/${'a'.repeat(8193 - cursor.length - 2)}`]) {
    expect(parseListSpacesRequest(request([...base, ['cursor', value]]))).toEqual({ tag: 'invalid', error: 'InvalidCursor' });
  }
});
