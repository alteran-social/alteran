#!/usr/bin/env -S deno run -A
/**
 * Import CAR file directly into D1 database
 * This bypasses Workers CPU limits by running locally
 *
 * This script:
 * 1. Parses the CAR file and extracts all records
 * 2. Rebuilds the MST from scratch using those records
 * 3. Stores all MST blocks (including intermediate nodes)
 * 4. Creates a proper commit pointing to the rebuilt MST
 */

import { parseCarFile } from '../src/lib/car-reader';
import * as dagCbor from '@ipld/dag-cbor';
import { CID } from 'multiformats/cid';
import { readFileSync, writeFileSync } from 'node:fs';
import { execSync } from 'node:child_process';
import * as uint8arrays from 'uint8arrays';
import { MST } from '../src/lib/mst/mst';
import { cidForCbor } from '../src/lib/mst/util';

const DB_NAME = process.env.DB_NAME || 'alteran';
const USE_REMOTE = process.env.USE_REMOTE !== 'false'; // Default to remote
const CAR_FILE = process.argv[2];
let DID = process.argv[3];

if (!CAR_FILE) {
  console.error('Usage: bun scripts/import-car-to-d1.ts <car-file> [did]');
  console.error('Example: bun scripts/import-car-to-d1.ts repo.car did:plc:xxxxx');
  console.error('');
  console.error('Environment variables:');
  console.error('  DB_NAME=<name>        D1 database name (default: alteran)');
  console.error('  USE_REMOTE=false      Use local D1 instead of remote (default: true)');
  process.exit(1);
}

console.log(`[INFO] Target: ${USE_REMOTE ? 'REMOTE' : 'LOCAL'} database`);

console.log(`[INFO] Importing ${CAR_FILE} for ${DID} into ${DB_NAME}`);

// Simple in-memory blockstore for MST building
class MemoryBlockstore {
  private blocks = new Map<string, Uint8Array>();

  async put(cid: CID, bytes: Uint8Array): Promise<void> {
    this.blocks.set(cid.toString(), bytes);
  }

  async get(cid: CID): Promise<Uint8Array | null> {
    return this.blocks.get(cid.toString()) || null;
  }

  async has(cid: CID): Promise<boolean> {
    return this.blocks.has(cid.toString());
  }

  async getMany(cids: CID[]): Promise<{ blocks: Map<string, Uint8Array>; missing: CID[] }> {
    const blocks = new Map<string, Uint8Array>();
    const missing: CID[] = [];
    for (const cid of cids) {
      const bytes = this.blocks.get(cid.toString());
      if (bytes) {
        blocks.set(cid.toString(), bytes);
      } else {
        missing.push(cid);
      }
    }
    return { blocks, missing };
  }

  async readObj<T = any>(cid: CID): Promise<T> {
    const bytes = await this.get(cid);
    if (!bytes) throw new Error(`Block not found: ${cid}`);
    return dagCbor.decode(bytes) as T;
  }

  getAllBlocks(): Array<{ cid: CID; bytes: Uint8Array }> {
    const result: Array<{ cid: CID; bytes: Uint8Array }> = [];
    for (const [cidStr, bytes] of this.blocks.entries()) {
      result.push({ cid: CID.parse(cidStr), bytes });
    }
    return result;
  }
}

// Read and parse CAR file
const carBytes = new Uint8Array(readFileSync(CAR_FILE));
const { header, blocks } = parseCarFile(carBytes);

console.log(`[INFO] Parsed CAR file: ${blocks.length} blocks`);

// Get root commit
const rootCid = header.roots[0];
if (!rootCid) {
  console.error('[ERROR] CAR file has no root CID');
  process.exit(1);
}

const commitBlock = blocks.find(b => b.cid.equals(rootCid));
if (!commitBlock) {
  console.error('[ERROR] Root commit block not found');
  process.exit(1);
}

const commit = dagCbor.decode(commitBlock.bytes) as any;
const rev = commit.rev || commit.version || '1';
// If DID param was omitted, prefer commit.did
if (!DID) {
  if (typeof commit.did === 'string' && commit.did.startsWith('did:')) {
    DID = commit.did;
    console.log(`[INFO] Inferred DID from CAR: ${DID}`);
  } else {
    console.error('[ERROR] DID not provided and not present in CAR commit');
    process.exit(1);
  }
}
const dataCid = commit.data;

console.log(`[INFO] Commit: ${rootCid.toString()}, Rev: ${rev}`);

// Build a block map for MST walking
const blockMap = new Map<string, Uint8Array>();
for (const block of blocks) {
  blockMap.set(block.cid.toString(), block.bytes);
}

// Walk MST and collect records
console.log(`[INFO] Walking MST to index records...`);
const mstRootCid = typeof dataCid === 'string' ? CID.parse(dataCid) : dataCid;
const records: Array<{ uri: string; cid: string; json: string }> = [];

try {
  await walkMST(mstRootCid, blockMap, DID, records);
  console.log(`[INFO] Found ${records.length} records in MST`);
} catch (error: any) {
  console.error(`[ERROR] Failed to walk MST: ${error.message}`);
  console.error(error.stack);
  process.exit(1);
}

// Rebuild MST from records to ensure all intermediate blocks exist
console.log(`[INFO] Rebuilding MST from ${records.length} records...`);
const memoryStore = new MemoryBlockstore();

// First, store all record blocks in memory store
const recordMap = new Map<string, { cid: CID; json: any }>();
for (const record of records) {
  const recordCid = CID.parse(record.cid);
  const recordData = JSON.parse(record.json);
  const recordBytes = dagCbor.encode(recordData);
  await memoryStore.put(recordCid, recordBytes);

  // Extract collection/rkey from URI: at://did/collection/rkey
  const key = record.uri.replace(`at://${DID}/`, '');
  recordMap.set(key, { cid: recordCid, json: recordData });
}

// Build MST from scratch (do NOT persist nodes during construction)
let mst = await MST.create(memoryStore, []);
const sortedKeys = Array.from(recordMap.keys()).sort();

console.log(`[INFO] Adding ${sortedKeys.length} records to MST...`);
for (const key of sortedKeys) {
  const record = recordMap.get(key)!;
  // Do not swallow add errors. A silently-skipped record ends up in the
  // `record` table but absent from the MST, which makes deleteRecord on that
  // rkey silently no-op and leaves the AppView with ghost entries it can
  // never undo. Abort so the import can be diagnosed and re-run.
  mst = await mst.add(key, record.cid);
}

// Calculate rebuilt MST root and collect all MST blocks to persist
const rebuiltMstRoot = await mst.getPointer();
console.log(`[INFO] Rebuilt MST root: ${rebuiltMstRoot.toString()}`);

// Compare with CAR commit's MST root
const originalMstRoot = typeof dataCid === 'string' ? CID.parse(dataCid) : dataCid;
const rootsMatch = rebuiltMstRoot.equals(originalMstRoot);
console.log(`[INFO] Original MST root: ${originalMstRoot.toString()} (match: ${rootsMatch})`);
if (!rootsMatch) {
  // Mismatch means we'd write a `repo_root` pointing at the original commit
  // while the locally-rebuilt MST blocks we persist have a different
  // structure. Either the CAR walk missed records or the rebuilt encoding
  // disagrees with the source. Abort rather than ship an inconsistent repo.
  console.error('[ERROR] Rebuilt MST root does not match the CAR commit root. Aborting.');
  process.exit(1);
}

// Gather all MST node blocks that are not in storage
const { blocks: mstBlocks } = await mst.getUnstoredBlocks();
let mstBlockCount = 0;
for (const [cid, bytes] of mstBlocks) {
  await memoryStore.put(cid, bytes);
  mstBlockCount++;
}
console.log(`[INFO] Collected ${mstBlockCount} MST blocks to store`);

// Always include the original commit block from the CAR
await memoryStore.put(rootCid, commitBlock.bytes);

// Also include the original MST node blocks from the CAR, to guarantee parity
console.log('[INFO] Collecting original MST node blocks from CAR...');
const seen = new Set<string>();
async function addMstFromCar(nodeCid: CID) {
  const cidStr = nodeCid.toString();
  if (seen.has(cidStr)) return;
  seen.add(cidStr);
  const nodeBytes = blockMap.get(cidStr);
  if (!nodeBytes) {
    console.warn(`[WARN] CAR missing MST node block: ${cidStr}`);
    return;
  }
  await memoryStore.put(nodeCid, nodeBytes);
  try {
    const node = dagCbor.decode(nodeBytes) as any;
    if (node?.l) {
      await addMstFromCar(CID.asCID(node.l) ?? CID.parse(String(node.l)));
    }
    if (Array.isArray(node?.e)) {
      for (const entry of node.e) {
        if (entry?.t) {
          await addMstFromCar(CID.asCID(entry.t) ?? CID.parse(String(entry.t)));
        }
      }
    }
  } catch (e: any) {
    console.warn(`[WARN] Failed to decode MST node from CAR: ${cidStr}: ${e?.message}`);
  }
}
await addMstFromCar(mstRootCid);
console.log(`[INFO] Added ${seen.size} original MST nodes from CAR`);

// Get all blocks to store
// - Union of: every block from the CAR (authoritative),
//             rebuilt MST blocks (to guarantee all changed node encodings exist),
//             and the commit block.
const allBlocksMap = new Map<string, { cid: CID; bytes: Uint8Array }>();

// 1) All blocks from CAR
for (const b of blocks) {
  allBlocksMap.set(b.cid.toString(), { cid: b.cid, bytes: b.bytes });
}

// 2) Rebuilt MST blocks + any record blocks we re-encoded into memoryStore
for (const b of memoryStore.getAllBlocks()) {
  const k = b.cid.toString();
  if (!allBlocksMap.has(k)) allBlocksMap.set(k, b);
}

// 3) Ensure commit block (rootCid) present (should already be from step 1)
if (!allBlocksMap.has(rootCid.toString())) {
  allBlocksMap.set(rootCid.toString(), { cid: rootCid, bytes: commitBlock.bytes });
}

const allBlocks = Array.from(allBlocksMap.values());
console.log(`[INFO] Total unique blocks to store: ${allBlocks.length} (CAR=${blocks.length}, union+rebuilt=${allBlocks.length - blocks.length})`);

// Generate SQL for batch insert
// D1 has a statement size limit, so we use smaller batches
const BATCH_SIZE = 50; // Reduced from 500 to avoid SQLITE_TOOBIG
const sqlStatements: string[] = [];

// Clean up previous import
sqlStatements.push(`DELETE FROM repo_root WHERE did = '${DID}';`);
sqlStatements.push(`DELETE FROM record WHERE did = '${DID}';`);
sqlStatements.push(`DELETE FROM account_state WHERE did = '${DID}';`);

console.log(`[INFO] Generating SQL for ${allBlocks.length} blocks...`);

// Insert blocks in batches
for (let i = 0; i < allBlocks.length; i += BATCH_SIZE) {
  const batch = allBlocks.slice(i, i + BATCH_SIZE);
  const values: string[] = [];

  for (const block of batch) {
    const cidStr = block.cid.toString();

    // Encode to base64
    let binary = '';
    const CHUNK_SIZE = 0x8000;
    for (let j = 0; j < block.bytes.length; j += CHUNK_SIZE) {
      binary += String.fromCharCode(...block.bytes.subarray(j, j + CHUNK_SIZE));
    }
    const base64 = btoa(binary);

    // Escape single quotes in base64 (though unlikely)
    const escapedBase64 = base64.replace(/'/g, "''");
    values.push(`('${cidStr}', '${escapedBase64}')`);
  }

  sqlStatements.push(
    `INSERT OR REPLACE INTO blockstore (cid, bytes) VALUES ${values.join(', ')};`
  );

  if ((i + BATCH_SIZE) % 1000 === 0 || i + BATCH_SIZE >= allBlocks.length) {
    console.log(`[INFO] Generated SQL for ${Math.min(i + BATCH_SIZE, allBlocks.length)}/${allBlocks.length} blocks`);
  }
}

// Insert commit_log entry (required for getRoot() to work), using the original commit from CAR
const commitCidStr = rootCid.toString();
const revStr = String(rev);

// Build a JSON representation compatible with PDS commit_log
const commitPrev = commit.prev ? (typeof commit.prev === 'string' ? commit.prev : CID.asCID(commit.prev)?.toString()) : null;
const commitDataObj = {
  did: commit.did || DID,
  version: commit.version || 3,
  data: (typeof commit.data === 'string' ? commit.data : CID.asCID(commit.data)?.toString()),
  rev: revStr,
  prev: commitPrev,
};
const commitData = JSON.stringify(commitDataObj);
const escapedCommitData = commitData.replace(/'/g, "''");

// Encode signature from original commit if present
let sigBase64 = '';
if (commit.sig) {
  const sigBytes: Uint8Array = commit.sig instanceof Uint8Array ? commit.sig : new Uint8Array(commit.sig);
  let bin = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < sigBytes.length; i += CHUNK) {
    bin += String.fromCharCode(...sigBytes.subarray(i, i + CHUNK));
  }
  sigBase64 = btoa(bin);
}
const escapedSig = sigBase64.replace(/'/g, "''");
const commitTs = Date.now();

sqlStatements.push(
  `INSERT OR REPLACE INTO commit_log (cid, rev, data, sig, ts) VALUES ('${commitCidStr}', '${revStr}', '${escapedCommitData}', '${escapedSig}', ${commitTs});`
);

// Insert repo_root pointing at the original commit
sqlStatements.push(
  `INSERT INTO repo_root (did, commit_cid, rev) VALUES ('${DID}', '${commitCidStr}', '${revStr}');`
);

// Insert records in batches
console.log(`[INFO] Generating SQL for ${records.length} records...`);
for (let i = 0; i < records.length; i += BATCH_SIZE) {
  const batch = records.slice(i, i + BATCH_SIZE);
  const values: string[] = [];

  for (const record of batch) {
    const escapedUri = record.uri.replace(/'/g, "''");
    const escapedCid = record.cid.replace(/'/g, "''");
    const escapedJson = record.json.replace(/'/g, "''");
    const createdAt = Date.now();

    values.push(`('${escapedUri}', '${DID}', '${escapedCid}', '${escapedJson}', ${createdAt})`);
  }

  sqlStatements.push(
    `INSERT OR REPLACE INTO record (uri, did, cid, json, created_at) VALUES ${values.join(', ')};`
  );

  if ((i + BATCH_SIZE) % 1000 === 0 || i + BATCH_SIZE >= records.length) {
    console.log(`[INFO] Generated SQL for ${Math.min(i + BATCH_SIZE, records.length)}/${records.length} records`);
  }
}

// Write SQL to temp file
const sqlFile = `/tmp/import-${Date.now()}.sql`;
writeFileSync(sqlFile, sqlStatements.join('\n'));

console.log(`[INFO] Generated ${sqlStatements.length} SQL statements`);
console.log(`[INFO] Executing SQL via wrangler...`);

try {
  // Execute SQL via wrangler (use --remote for production database)
  const remoteFlag = USE_REMOTE ? '--remote' : '';
  const cmd = `wrangler d1 execute ${DB_NAME} ${remoteFlag} --file=${sqlFile}`;

  console.log(`[INFO] Running: ${cmd}`);
  execSync(cmd, {
    stdio: 'inherit'
  });

  console.log(`[SUCCESS] Import completed successfully`);
  console.log(`[INFO] DID: ${DID}`);
  console.log(`[INFO] Commit: ${commitCidStr}`);
  console.log(`[INFO] Rev: ${revStr}`);
  console.log(`[INFO] Original MST Root: ${originalMstRoot.toString()}`);
  console.log(`[INFO] Rebuilt MST Root: ${rebuiltMstRoot.toString()} (match: ${rootsMatch})`);
  console.log(`[INFO] Total blocks stored: ${allBlocks.length}`);
  console.log(`[INFO] Records indexed: ${records.length}`);

  // Clean up temp file
  execSync(`rm ${sqlFile}`);
} catch (error: any) {
  console.error(`[ERROR] Failed to execute SQL: ${error.message}`);
  console.error(`[INFO] SQL file saved at: ${sqlFile}`);
  process.exit(1);
}

/**
 * Walk MST tree and collect all records
 */
async function walkMST(
  rootCid: CID,
  blockMap: Map<string, Uint8Array>,
  did: string,
  records: Array<{ uri: string; cid: string; json: string }>
): Promise<void> {
  const visited = new Set<string>();

  async function walkNode(nodeCid: CID, prefix: string = ''): Promise<void> {
    const cidStr = nodeCid.toString();

    // Avoid infinite loops
    if (visited.has(cidStr)) return;
    visited.add(cidStr);

    const nodeBytes = blockMap.get(cidStr);
    if (!nodeBytes) {
      console.error(`[WARN] Missing block: ${cidStr}`);
      return;
    }

    const node = dagCbor.decode(nodeBytes) as any;

    // MST node structure: { l: CID | null, e: Array<{ p: number, k: Uint8Array, v: CID, t: CID | null }> }
    if (!node.e || !Array.isArray(node.e)) {
      console.error(`[WARN] Invalid MST node structure: ${cidStr}`);
      return;
    }

    // Walk left subtree first
    if (node.l) {
      await walkNode(node.l, prefix);
    }

    // Process entries
    let lastKey = prefix;
    for (const entry of node.e) {
      // Reconstruct key from prefix compression
      const keyBytes = entry.k;
      const keyStr = uint8arrays.toString(keyBytes, 'ascii');
      const fullKey = lastKey.slice(0, entry.p) + keyStr;
      lastKey = fullKey;

      // Get record value
      const recordCid = entry.v;
      const recordBytes = blockMap.get(recordCid.toString());

      if (recordBytes) {
        try {
          const recordData = dagCbor.decode(recordBytes);
          const uri = `at://${did}/${fullKey}`;

          records.push({
            uri,
            cid: recordCid.toString(),
            json: JSON.stringify(recordData)
          });
        } catch (error: any) {
          console.error(`[WARN] Failed to decode record ${recordCid.toString()}: ${error.message}`);
        }
      } else {
        console.error(`[WARN] Missing record block: ${recordCid.toString()} for key: ${fullKey}`);
      }

      // Walk right subtree
      if (entry.t) {
        await walkNode(entry.t, lastKey);
      }
    }
  }

  await walkNode(rootCid);
}
