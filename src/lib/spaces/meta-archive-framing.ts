export const MAX_META_ARCHIVE_BYTES = 16 * 1024 * 1024;
export const MAX_META_LENGTH = 64 * 1024;
export const MAX_KEY_LENGTH = 4 * 1024;
export const MAX_VALUE_LENGTH = 1024 * 1024;
export const MAX_META_ENTRIES = 10_000;

export type MetaFrame = {
  readonly key: Uint8Array;
  readonly value: Uint8Array;
};
const MAGIC = [0x2a, 0x6c, 0x01, 0x00];

/** Copy only ordinary typed-array storage before parsing or returning it. */
export function copyBoundedBytes(value: unknown, maximum: number): Uint8Array {
  if (!(value instanceof Uint8Array)) throw invalid();
  const prototype = Object.getPrototypeOf(Uint8Array.prototype);
  const length = Reflect.get(prototype, "byteLength", value);
  const offset = Reflect.get(prototype, "byteOffset", value);
  const buffer = Reflect.get(prototype, "buffer", value);
  if (
    !Number.isSafeInteger(length) || length < 0 || length > maximum ||
    !Number.isSafeInteger(offset) || offset < 0 ||
    !(buffer instanceof ArrayBuffer)
  ) throw invalid();
  const copy = new Uint8Array(length);
  copy.set(new Uint8Array(buffer, offset, length));
  return copy;
}

export function readMetaFrames(
  input: unknown,
): { metadata: Uint8Array; pairs: readonly MetaFrame[] } {
  const bytes = copyBoundedBytes(input, MAX_META_ARCHIVE_BYTES);
  let offset = 0;
  for (const byte of MAGIC) if (bytes[offset++] !== byte) throw invalid();
  const readLength = (maximum: number): number => {
    let value = 0;
    for (let index = 0; index < 9; index++) {
      if (offset >= bytes.length) throw invalid();
      const byte = bytes[offset++];
      value += (byte & 0x7f) * 2 ** (7 * index);
      if (value > maximum) throw invalid();
      if (byte < 0x80) {
        if (index > 0 && byte === 0) throw invalid();
        return value;
      }
    }
    throw invalid();
  };
  const readFrame = (maximum: number): Uint8Array => {
    const length = readLength(maximum);
    if (length > bytes.length - offset) throw invalid();
    const frame = bytes.subarray(offset, offset + length);
    offset += length;
    return frame;
  };
  const metadata = readFrame(MAX_META_LENGTH);
  const pairs: MetaFrame[] = [];
  for (;;) {
    if (offset >= bytes.length) throw invalid();
    const control = bytes[offset++];
    if (control === 0) break;
    if (control !== 1 || pairs.length >= MAX_META_ENTRIES) throw invalid();
    pairs.push({
      key: readFrame(MAX_KEY_LENGTH),
      value: readFrame(MAX_VALUE_LENGTH),
    });
  }
  if (offset !== bytes.length) throw invalid();
  return { metadata, pairs };
}

export function writeMetaFrames(
  metadata: Uint8Array,
  pairs: readonly MetaFrame[],
): Uint8Array {
  if (metadata.length > MAX_META_LENGTH || pairs.length > MAX_META_ENTRIES) {
    throw invalid();
  }
  const frames: Uint8Array[] = [
    Uint8Array.from(MAGIC),
    varint(metadata.length),
    metadata,
  ];
  let total = frames.reduce((sum, frame) => sum + frame.length, 1);
  for (const { key, value } of pairs) {
    if (key.length > MAX_KEY_LENGTH || value.length > MAX_VALUE_LENGTH) {
      throw invalid();
    }
    const keyLength = varint(key.length);
    const valueLength = varint(value.length);
    total += 1 + keyLength.length + key.length + valueLength.length +
      value.length;
    if (total > MAX_META_ARCHIVE_BYTES) throw invalid();
    frames.push(Uint8Array.of(1), keyLength, key, valueLength, value);
  }
  if (total > MAX_META_ARCHIVE_BYTES) throw invalid();
  const result = new Uint8Array(total);
  let offset = 0;
  for (const frame of frames) {
    result.set(frame, offset);
    offset += frame.length;
  }
  result[offset] = 0;
  return result;
}

function varint(value: number): Uint8Array {
  const bytes: number[] = [];
  while (value >= 0x80) {
    bytes.push((value % 0x80) | 0x80);
    value = Math.floor(value / 0x80);
  }
  bytes.push(value);
  return Uint8Array.from(bytes);
}

function invalid(): Error {
  return new Error("Invalid bounded STAR framing");
}
