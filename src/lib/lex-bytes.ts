export function isLexBytesBase64(value: string): boolean {
  const bodyEnd = base64BodyEnd(value);
  if (bodyEnd % 4 === 1) return false;
  for (let index = 0; index < bodyEnd; index++) {
    if (base64Value(value.charCodeAt(index)) < 0) return false;
  }
  return !value.slice(0, bodyEnd).includes("=");
}

export function decodeLexBytes(value: string): Uint8Array {
  if (!isLexBytesBase64(value)) {
    throw new TypeError("Invalid base64 bytes");
  }
  const bodyEnd = base64BodyEnd(value);
  const result = new Uint8Array(Math.floor((bodyEnd * 3) / 4));
  let outputIndex = 0;

  for (let index = 0; index <= bodyEnd - 4; index += 4) {
    const chunk = (base64Value(value.charCodeAt(index)) << 18) |
      (base64Value(value.charCodeAt(index + 1)) << 12) |
      (base64Value(value.charCodeAt(index + 2)) << 6) |
      base64Value(value.charCodeAt(index + 3));
    result[outputIndex++] = (chunk >> 16) & 0xff;
    result[outputIndex++] = (chunk >> 8) & 0xff;
    result[outputIndex++] = chunk & 0xff;
  }

  const remaining = bodyEnd % 4;
  if (remaining === 2) {
    const chunk = (base64Value(value.charCodeAt(bodyEnd - 2)) << 18) |
      (base64Value(value.charCodeAt(bodyEnd - 1)) << 12);
    result[result.length - 1] = (chunk >> 16) & 0xff;
  } else if (remaining === 3) {
    const chunk = (base64Value(value.charCodeAt(bodyEnd - 3)) << 18) |
      (base64Value(value.charCodeAt(bodyEnd - 2)) << 12) |
      (base64Value(value.charCodeAt(bodyEnd - 1)) << 6);
    result[result.length - 2] = (chunk >> 16) & 0xff;
    result[result.length - 1] = (chunk >> 8) & 0xff;
  }

  return result;
}

function base64BodyEnd(value: string): number {
  let bodyEnd = value.length;
  while (bodyEnd > 0 && value.charCodeAt(bodyEnd - 1) === 0x3d) {
    bodyEnd--;
  }
  return bodyEnd;
}

function base64Value(code: number): number {
  if (code >= 0x41 && code <= 0x5a) return code - 0x41;
  if (code >= 0x61 && code <= 0x7a) return code - 0x61 + 26;
  if (code >= 0x30 && code <= 0x39) return code - 0x30 + 52;
  if (code === 0x2b || code === 0x2d) return 62;
  if (code === 0x2f || code === 0x5f) return 63;
  return -1;
}
