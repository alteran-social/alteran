import type { APIContext } from 'astro';
import { CID } from 'multiformats/cid';
import * as dagCbor from '@ipld/dag-cbor';
import { sha256 } from 'multiformats/hashes/sha2';

export function tryParse(json: string): unknown {
  try {
    return JSON.parse(json);
  } catch {
    return json;
  }
}

// JSON helper with size cap
export async function readJson(request: Request): Promise<any> {
  const max = 64 * 1024;
  const text = await request.text();
  if (text.length > max) throw new Error('PayloadTooLarge');
  return JSON.parse(text || '{}');
}

export async function readJsonBounded(env: any, request: Request): Promise<any> {
  const raw = (env.PDS_MAX_JSON_BYTES as string | undefined) ?? '65536';
  const max = Number(raw) > 0 ? Number(raw) : 65536;
  const text = await request.text();
  if (text.length > max) {
    const err: any = new Error('PayloadTooLarge');
    err.code = 'PayloadTooLarge';
    throw err;
  }
  return JSON.parse(text || '{}');
}

export function bearerToken(request: Request): string | null {
  const auth = request.headers.get('authorization');
  if (!auth) return null;
  if (auth.startsWith('Bearer ')) return auth.slice(7);
  if (auth.startsWith('DPoP ')) return auth.slice(5);
  return null;
}

export function isAllowedMime(env: any, mime: string): boolean {
  const def = [
    // Images
    'image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/avif',
    // Videos
    'video/mp4', 'video/mpeg', 'video/webm', 'video/quicktime',
    // Audio
    'audio/mpeg', 'audio/mp4', 'audio/wav', 'audio/webm',
    // JSON (for some Bluesky data)
    'application/json',
    // Generic fallback
    'application/octet-stream'
  ];
  const raw = (env.PDS_ALLOWED_MIME as string | undefined) ?? def.join(',');
  const set = new Set(raw.split(',').map((s) => s.trim()).filter(Boolean));

  // Extract base MIME type (remove charset and other parameters)
  const baseMime = mime.toLowerCase().split(';')[0].trim();

  return set.has(baseMime);
}

export function baseMime(mime: string | null | undefined): string {
  if (!mime) return 'application/octet-stream';
  return mime.toLowerCase().split(';')[0].trim();
}

// Best-effort MIME sniffing for common image/video/audio formats.
// Prefer this over client-provided header when possible, mirroring upstream PDS.
export function sniffMime(buf: ArrayBuffer): string | null {
  const bytes = new Uint8Array(buf);
  const len = bytes.length;
  const ascii = (start: number, n: number) =>
    String.fromCharCode(...bytes.slice(start, start + n));

  if (len >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) {
    return 'image/jpeg';
  }
  if (
    len >= 8 &&
    bytes[0] === 0x89 && ascii(1, 3) === 'PNG' && bytes[4] === 0x0d && bytes[5] === 0x0a && bytes[6] === 0x1a && bytes[7] === 0x0a
  ) {
    return 'image/png';
  }
  if (len >= 6) {
    const sig6 = ascii(0, 6);
    if (sig6 === 'GIF87a' || sig6 === 'GIF89a') return 'image/gif';
  }
  if (len >= 12 && ascii(0, 4) === 'RIFF' && ascii(8, 4) === 'WEBP') {
    return 'image/webp';
  }
  // ISO BMFF / MP4 / AVIF / QuickTime: find 'ftyp' within first 256 bytes
  {
    const window = Math.min(len, 256);
    for (let i = 0; i + 8 <= window; i++) {
      if (ascii(i, 4) === 'ftyp') {
        const brand = ascii(i + 4, 4);
        const mp4Brands = new Set(['isom', 'iso2', 'mp41', 'mp42', 'avc1', 'MSNV', '3gp4', 'M4V ']);
        if (brand === 'avif' || brand === 'avis' || brand === 'mif1' || brand === 'msf1') return 'image/avif';
        if (brand === 'qt  ') return 'video/quicktime';
        if (mp4Brands.has(brand)) return 'video/mp4';
        // Unknown brand: still likely MP4 container
        return 'video/mp4';
      }
    }
  }
  // WebM/Matroska (EBML)
  if (len >= 4 && bytes[0] === 0x1a && bytes[1] === 0x45 && bytes[2] === 0xdf && bytes[3] === 0xa3) {
    // Could be audio/webm or video/webm; default to video/webm
    return 'video/webm';
  }
  return null;
}

export function randomRkey(): string {
  return crypto.randomUUID().replace(/-/g, '').substring(0, 13);
}

export async function cidFromJson(json: any): Promise<CID> {
  const bytes = dagCbor.encode(json);
  const hash = await sha256.digest(bytes);
  return CID.create(1, dagCbor.code, hash);
}
