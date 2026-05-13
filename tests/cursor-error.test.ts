import { describe, it, expect } from 'bun:test';
import { checkCursor } from '../src/lib/firehose/validation';
import * as dagCbor from '@ipld/dag-cbor';
import { FrameType } from '../src/lib/firehose/frames';

function decodeFrame(bytes: Uint8Array): { header: any; body: any } {
  let headerLen = 0;
  for (let i = 1; i <= bytes.byteLength; i++) {
    try {
      dagCbor.decode(bytes.slice(0, i));
      headerLen = i;
      break;
    } catch {
      // keep scanning for the first complete DAG-CBOR object
    }
  }
  if (headerLen === 0) throw new Error('could not find header boundary');
  return {
    header: dagCbor.decode(bytes.slice(0, headerLen)),
    body: dagCbor.decode(bytes.slice(headerLen)),
  };
}

// checkCursor emits event-stream frames as DAG-CBOR(header) || DAG-CBOR(body).
describe('cursor validation', () => {
  it('returns null when cursor is at or behind the current seq', () => {
    expect(checkCursor(0, 0)).toBeNull();
    expect(checkCursor(50, 100)).toBeNull();
  });

  it('returns a FutureCursor error frame when cursor is ahead', () => {
    const bytes = checkCursor(150, 100);
    expect(bytes).toBeInstanceOf(Uint8Array);
    const decoded = decodeFrame(bytes as Uint8Array);
    expect(decoded.header).toEqual({ op: FrameType.Error });
    expect(decoded.body).toEqual({
      error: 'FutureCursor',
      message: 'Cursor is ahead of current sequence',
    });
  });
});
