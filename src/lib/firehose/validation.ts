import { encodeErrorFrame } from './frames';

export function checkCursor(cursor: number, currentSeq: number): Uint8Array | null {
  if (Number.isFinite(cursor) && Number.isFinite(currentSeq) && cursor > currentSeq) {
    return encodeErrorFrame('FutureCursor', 'Cursor is ahead of current sequence');
  }
  return null;
}
