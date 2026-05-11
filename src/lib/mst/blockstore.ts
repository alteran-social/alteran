import { CID } from 'multiformats/cid';
import { errorMessage } from '../errors';
import * as dagCbor from '@ipld/dag-cbor';
import type { Env } from '../../env';
import { drizzle } from 'drizzle-orm/d1';
import { blockstore } from '../../db/schema';
import { eq } from 'drizzle-orm';

/**
 * Interface for reading blocks from storage
 */
export interface ReadableBlockstore {
  get(cid: CID): Promise<Uint8Array | null>;
  has(cid: CID): Promise<boolean>;
  getMany(cids: CID[]): Promise<{ blocks: Map<string, Uint8Array>; missing: CID[] }>;
  readObj<T>(cid: CID): Promise<T>;
}

/**
 * Interface for writing blocks to storage
 */
export interface WritableBlockstore extends ReadableBlockstore {
  put(cid: CID, bytes: Uint8Array): Promise<void>;
  putMany(blocks: Map<CID, Uint8Array>): Promise<void>;
}

/**
 * D1-backed blockstore implementation
 */
export class D1Blockstore implements WritableBlockstore {
  constructor(private env: Env) {}

  async get(cid: CID): Promise<Uint8Array | null> {
    const row = await this.env.DB.prepare(
      `SELECT bytes FROM blockstore WHERE cid = ? LIMIT 1`
    ).bind(cid.toString()).first();

    if (!row) return null;
    const base64 = (row as any).bytes as string | null | undefined;
    if (!base64 || base64.length === 0) return null;
    return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
  }

  async has(cid: CID): Promise<boolean> {
    // Treat rows with NULL or empty bytes as missing
    const row = await this.env.DB.prepare(
      `SELECT bytes FROM blockstore WHERE cid = ? LIMIT 1`
    ).bind(cid.toString()).first();

    if (!row) return false;
    const bytes = (row as any).bytes as string | null | undefined;
    return typeof bytes === 'string' && bytes.length > 0;
  }

  async getMany(cids: CID[]): Promise<{ blocks: Map<string, Uint8Array>; missing: CID[] }> {
    const blocks = new Map<string, Uint8Array>();
    const missing: CID[] = [];

    if (cids.length === 0) return { blocks, missing };

    // Fetch in chunks using a single IN-clause per chunk.
    // Cloudflare D1 can error with "too many SQL variables" on large IN lists,
    // so keep this conservatively small.
    const BATCH = 50;
    for (let i = 0; i < cids.length; i += BATCH) {
      const chunk = cids.slice(i, i + BATCH);
      const placeholders = new Array(chunk.length).fill('?').join(',');
      const stmt = this.env.DB.prepare(`SELECT cid, bytes FROM blockstore WHERE cid IN (${placeholders})`);
      const binds = chunk.map((c) => c.toString());
      const response = await stmt.bind(...binds).all();
      const rows = (response.results ?? []) as Array<{ cid: string; bytes: string }>;
      const got = new Set<string>();
      for (const row of rows) {
        got.add(row.cid);
        if (row.bytes && row.bytes.length > 0) {
          const u8 = Uint8Array.from(atob(row.bytes), (c) => c.charCodeAt(0));
          blocks.set(row.cid, u8);
        }
      }
      for (const c of chunk) {
        if (!got.has(c.toString())) missing.push(c);
      }
    }

    return { blocks, missing };
  }

  async put(cid: CID, bytes: Uint8Array): Promise<void> {
    const cidStr = cid.toString();
    // Encode Uint8Array to base64 string for storage. Chunk to avoid call-stack limits.
    let binary = '';
    const CHUNK_SIZE = 0x8000;
    for (let i = 0; i < bytes.length; i += CHUNK_SIZE) {
      binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK_SIZE));
    }
    const base64 = btoa(binary);

    // Always upsert: replace rows with NULL/empty bytes
    try {
      await this.env.DB.prepare(
        `INSERT OR REPLACE INTO blockstore (cid, bytes) VALUES (?, ?)`
      ).bind(cidStr, base64).run();
    } catch (error) {
      console.error(JSON.stringify({
        level: 'error',
        type: 'blockstore_put',
        cid: cidStr,
        size: bytes.byteLength,
        message: errorMessage(error),
      }));
      throw error;
    }
  }

  async putMany(blocks: Map<CID, Uint8Array>): Promise<void> {
    const BATCH_SIZE = 100;
    const entries = Array.from(blocks.entries());
    for (let i = 0; i < entries.length; i += BATCH_SIZE) {
      const batch = entries.slice(i, i + BATCH_SIZE);
      const stmts = [] as Array<ReturnType<typeof this.env.DB['prepare']>>;
      for (const [cid, bytes] of batch) {
        const cidStr = cid.toString();
        let binary = '';
        const CHUNK_SIZE = 0x8000;
        for (let j = 0; j < bytes.length; j += CHUNK_SIZE) {
          binary += String.fromCharCode(...bytes.subarray(j, j + CHUNK_SIZE));
        }
        const base64 = btoa(binary);
        stmts.push(
          this.env.DB.prepare(`INSERT OR REPLACE INTO blockstore (cid, bytes) VALUES (?, ?)`)
            .bind(cidStr, base64)
        );
      }
      if (stmts.length > 0) {
        await this.env.DB.batch(stmts);
      }
    }
  }

  /**
   * Read and decode a CBOR object from the blockstore
   */
  async readObj<T>(cid: CID): Promise<T> {
    const bytes = await this.get(cid);
    if (!bytes) {
      console.error('[Blockstore] Block not found:', cid.toString());
      console.error('[Blockstore] Stack trace:', new Error().stack);
      throw new Error(`Block not found: ${cid.toString()}`);
    }
    return dagCbor.decode(bytes) as T;
  }
}
