import { describe, it, expect } from 'bun:test';
import { checkCursor } from '../src/lib/firehose/validation';
import * as dagCbor from '@ipld/dag-cbor';

// checkCursor now emits a spec-compliant #info event (single CBOR object with
// a $type discriminator), not a length-prefixed error frame.
describe('cursor validation', () => {
  it('returns null when cursor is at or behind the current seq', () => {
    expect(checkCursor(0, 0)).toBeNull();
    expect(checkCursor(50, 100)).toBeNull();
  });

  it('returns an #info OutdatedCursor event when cursor is ahead', () => {
    const bytes = checkCursor(150, 100);
    expect(bytes).toBeInstanceOf(Uint8Array);
    const decoded = dagCbor.decode(bytes as Uint8Array) as Record<string, unknown>;
    expect(decoded.$type).toBe('#info');
    expect(decoded.name).toBe('OutdatedCursor');
  });
});

