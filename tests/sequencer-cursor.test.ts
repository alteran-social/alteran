import { describe, it, expect } from 'bun:test';
import { parseCursorParam } from '../src/worker/sequencer/upgrade';
import { InvalidRequest } from '../src/lib/errors';

describe('parseCursorParam', () => {
  it('defaults missing param to 0', () => {
    expect(parseCursorParam(null)).toBe(0);
  });

  it('parses a non-negative integer', () => {
    expect(parseCursorParam('42')).toBe(42);
    expect(parseCursorParam('0')).toBe(0);
  });

  it('rejects non-numeric values', () => {
    expect(() => parseCursorParam('abc')).toThrow(InvalidRequest);
    expect(() => parseCursorParam('')).toThrow(InvalidRequest);
  });

  it('rejects negatives', () => {
    expect(() => parseCursorParam('-1')).toThrow(InvalidRequest);
  });

  it('rejects floats', () => {
    expect(() => parseCursorParam('1.5')).toThrow(InvalidRequest);
  });

  it('rejects Infinity', () => {
    expect(() => parseCursorParam('Infinity')).toThrow(InvalidRequest);
  });
});
