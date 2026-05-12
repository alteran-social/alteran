// Types via tsconfig.app.json
import type { R2ObjectBody } from '@cloudflare/workers-types';
import type { Env } from '../env';

export type PutOptions = {
  contentType?: string;
  maxBytes?: number; // default from env or 5 MiB
};

export type PutResult = {
  key: string;
  size: number;
  sha256: string; // base64url
};

type BlobBody = ArrayBuffer | ArrayBufferView;

export class R2BlobStore {
  constructor(private env: Env) {}

  private maxBytes(defaultMax = 5 * 1024 * 1024): number {
    const raw = (this.env as any).PDS_MAX_BLOB_SIZE as string | undefined;
    const n = raw ? Number(raw) : defaultMax;
    return Number.isFinite(n) && n > 0 ? n : defaultMax;
  }

  private static asUint8Array(data: BlobBody): Uint8Array {
    if (data instanceof ArrayBuffer) return new Uint8Array(data);
    if (ArrayBuffer.isView(data)) {
      const view = data as ArrayBufferView;
      return new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
    }
    // Fallback should never happen because BlobBody restricts input, but keep typing satisfied
    return new Uint8Array(data as ArrayBuffer);
  }

  private static toArrayBuffer(data: Uint8Array): ArrayBuffer {
    const bufferLike = data.buffer;
    if (bufferLike instanceof ArrayBuffer) {
      if (data.byteOffset === 0 && data.byteLength === bufferLike.byteLength) {
        return bufferLike;
      }
      return bufferLike.slice(data.byteOffset, data.byteOffset + data.byteLength);
    }
    const buffer = new ArrayBuffer(data.byteLength);
    new Uint8Array(buffer).set(data);
    return buffer;
  }

  private static b64url(bytes: ArrayBuffer | Uint8Array): string {
    const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    let s = '';
    for (const v of view) s += String.fromCharCode(v);
    return btoa(s).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
  }

  private static hex(bytes: Uint8Array): string {
    return Array.from(bytes).map((v) => v.toString(16).padStart(2, '0')).join('');
  }

  private static cidKey(shaB64url: string, prefix = 'blobs/by-cid/'): string {
    return `${prefix}${shaB64url}`;
  }

  async put(body: BlobBody, opts: PutOptions = {}): Promise<PutResult> {
    const view = R2BlobStore.asUint8Array(body);
    const size = view.byteLength;
    const limit = opts.maxBytes ?? this.maxBytes();
    if (size > limit) throw new Error(`BlobTooLarge:${size}>${limit}`);

    const contentType = opts.contentType ?? 'application/octet-stream';
    const sha = await crypto.subtle.digest('SHA-256', R2BlobStore.toArrayBuffer(view));
    const shaB64 = R2BlobStore.b64url(sha);
    const key = R2BlobStore.cidKey(shaB64);
    const buffer = R2BlobStore.toArrayBuffer(view);
    await this.env.ALTERAN_BLOBS.put(key, buffer, { httpMetadata: { contentType } });
    return { key, size, sha256: shaB64 };
  }

  async get(key: string): Promise<R2ObjectBody | null> {
    return this.env.ALTERAN_BLOBS.get(key);
  }

  async delete(key: string): Promise<void> {
    await this.env.ALTERAN_BLOBS.delete(key);
  }
}
