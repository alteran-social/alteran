import { describe, it } from './helpers/bdd';
import { expect } from '@std/expect';
import { bytesToHex } from '@noble/hashes/utils.js';
import { Buffer } from 'node:buffer';
import {
  applySpaceSetHashChanges,
  SPACE_SET_HASH_STATE_BYTES,
  spaceRecordHashElement,
  spaceSetHashDigest,
} from '../src/lib/spaces/lthash';

describe('Spaces set hash', () => {
  it('matches the reference empty-repository digest', () => {
    const state = applySpaceSetHashChanges(null, []);
    expect(state.byteLength).toBe(SPACE_SET_HASH_STATE_BYTES);
    expect(bytesToHex(spaceSetHashDigest(state))).toBe(
      'e5a00aa9991ac8a5ee3109844d84a55583bd20572ad3ffcd42792f3c36b183ad',
    );
  });

  it('matches the reference BLAKE3 expansion and lane arithmetic vector', () => {
    const state = applySpaceSetHashChanges(null, [
      { action: 'add', element: 'one' },
      { action: 'add', element: 'two' },
    ]);
    expect(bytesToHex(spaceSetHashDigest(state))).toBe(
      'ae05cb6d224379d9710c290c8529945c5b0e0fde9ead30b9699057ce701c63e7',
    );
  });

  it('replays record replacement and deletion independently of insertion order', () => {
    const first = spaceRecordHashElement('app.example.note', 'one', 'cid-a');
    const second = spaceRecordHashElement('app.example.note', 'two', 'cid-b');
    const replacement = spaceRecordHashElement('app.example.note', 'one', 'cid-c');
    const initial = applySpaceSetHashChanges(null, [
      { action: 'add', element: first },
      { action: 'add', element: second },
    ]);
    const updated = applySpaceSetHashChanges(initial, [
      { action: 'remove', element: first },
      { action: 'add', element: replacement },
      { action: 'remove', element: second },
    ]);
    expect(updated).toEqual(applySpaceSetHashChanges(null, [
      { action: 'add', element: replacement },
    ]));
    expect(applySpaceSetHashChanges(updated, [{ action: 'remove', element: replacement }]))
      .toEqual(new Uint8Array(SPACE_SET_HASH_STATE_BYTES));
  });

  it('does not mutate the persisted input state', () => {
    const original = applySpaceSetHashChanges(null, [{ action: 'add', element: 'one' }]);
    const snapshot = original.slice();
    const next = applySpaceSetHashChanges(original, [{ action: 'add', element: 'two' }]);
    expect(original).toEqual(snapshot);
    expect(next).not.toEqual(original);
  });

  it('does not mutate a Buffer-backed persisted state', () => {
    const original = Buffer.alloc(SPACE_SET_HASH_STATE_BYTES);
    const next = applySpaceSetHashChanges(original, [{ action: 'add', element: 'one' }]);
    expect(original).toEqual(Buffer.alloc(SPACE_SET_HASH_STATE_BYTES));
    expect(next).not.toEqual(original);
  });

  it('rejects malformed persisted states', () => {
    const invalid = new Uint8Array(32);
    expect(() => applySpaceSetHashChanges(invalid, [])).toThrow(RangeError);
    expect(() => spaceSetHashDigest(invalid)).toThrow(RangeError);
  });
});
