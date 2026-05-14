import type { D1PreparedStatement } from '@cloudflare/workers-types';
import { isValidNsid, isValidRecordKey, isValidTid } from '@atproto/syntax';
import * as dagCbor from '@ipld/dag-cbor';
import { CID } from 'multiformats/cid';
import type { Env } from '../../env';
import { parseCarFile, validateBlock, type CarBlock } from '../../lib/car-reader';
import { verifyCommit } from '../../lib/commit';
import { MST, type ReadableBlockstore } from '../../lib/mst';
import { validateRawRecord } from '../../lib/repo-write-validation';
import { putRecordStatements, setRecordBlobUsageStatements, type CommitGuard } from '../../db/dal';
import { resolveSecret } from '../../lib/secrets';
import { extractBskyLegacyBlobRefs } from '../../lib/blob-refs';

export class RepoImportError extends Error {
  constructor(
    public readonly error: string,
    message: string,
    public readonly status = 400,
  ) {
    super(message);
  }
}

type ImportedCommit = {
  cid: CID;
  did: string;
  version: 3;
  data: CID;
  rev: string;
  prev: CID | null;
  sig: Uint8Array;
};

type ImportedRecord = {
  path: string;
  uri: string;
  cid: CID;
  json: string;
  record: Record<string, unknown>;
};

type ImportedBlobRef = {
  cid: string;
  mimeType: string;
  size: number | null;
};

type ImportedRepo = {
  commit: ImportedCommit;
  blocksToStore: CarBlock[];
  records: ImportedRecord[];
};

export type ImportRepoResult = {
  commitCid: string;
  rev: string;
  recordCount: number;
};

class MemoryBlockstore implements ReadableBlockstore {
  constructor(private readonly blocks: Map<string, Uint8Array>) {}

  async get(cid: CID): Promise<Uint8Array | null> {
    return this.blocks.get(cid.toString()) ?? null;
  }

  async has(cid: CID): Promise<boolean> {
    return this.blocks.has(cid.toString());
  }

  async getMany(cids: CID[]): Promise<{ blocks: Map<string, Uint8Array>; missing: CID[] }> {
    const blocks = new Map<string, Uint8Array>();
    const missing: CID[] = [];
    for (const cid of cids) {
      const bytes = await this.get(cid);
      if (bytes) {
        blocks.set(cid.toString(), bytes);
      } else {
        missing.push(cid);
      }
    }
    return { blocks, missing };
  }

  async readObj<T>(cid: CID): Promise<T> {
    const bytes = await this.get(cid);
    if (!bytes) throw new Error(`Block not found: ${cid.toString()}`);
    return dagCbor.decode(bytes) as T;
  }
}

export async function importRepoCar(
  env: Env,
  did: string,
  bytes: Uint8Array,
): Promise<ImportRepoResult> {
  const imported = await parseAndVerifyImport(env, did, bytes);
  await applyImportedRepo(env, did, imported);
  return {
    commitCid: imported.commit.cid.toString(),
    rev: imported.commit.rev,
    recordCount: imported.records.length,
  };
}

async function parseAndVerifyImport(env: Env, did: string, bytes: Uint8Array): Promise<ImportedRepo> {
  let parsed: ReturnType<typeof parseCarFile>;
  try {
    parsed = parseCarFile(bytes);
  } catch (error) {
    throw invalidImport('invalid CAR file');
  }

  if (parsed.header.roots.length < 1) {
    throw invalidImport('CAR must contain at least one root');
  }

  const blocksByCid = indexCarBlocks(parsed.blocks);
  const root = asCid(parsed.header.roots[0], 'CAR root');
  const rootBlock = blocksByCid.get(root.toString());
  if (!rootBlock) {
    throw invalidImport('CAR root block is missing');
  }
  await validateDagCborBlock(rootBlock);

  const commit = decodeCommit(root, rootBlock, did);
  await verifyImportedCommitSignature(env, commit);
  const { records, reachableMstCids } = await walkAndVerifyRecords(blocksByCid, commit);
  await verifyCanonicalMst(commit.data, records);
  const blocksToStore = collectBlocksToStore(blocksByCid, commit, records, reachableMstCids);

  return {
    commit,
    blocksToStore,
    records,
  };
}

function indexCarBlocks(blocks: CarBlock[]): Map<string, CarBlock> {
  const blocksByCid = new Map<string, CarBlock>();
  for (const block of blocks) {
    const cid = block.cid.toString();
    const existing = blocksByCid.get(cid);
    if (existing) {
      if (!bytesEqual(existing.bytes, block.bytes)) {
        throw invalidImport(`duplicate block has different bytes: ${cid}`);
      }
      continue;
    }
    blocksByCid.set(cid, block);
  }
  return blocksByCid;
}

async function validateDagCborBlock(block: CarBlock): Promise<void> {
  if (!await validateBlock(block)) {
    throw invalidImport(`block CID does not match canonical dag-cbor bytes: ${block.cid.toString()}`);
  }
}

function decodeCommit(root: CID, block: CarBlock, did: string): ImportedCommit {
  let decoded: unknown;
  try {
    decoded = dagCbor.decode(block.bytes);
  } catch {
    throw invalidImport('commit block is not valid dag-cbor');
  }

  if (!isPlainObject(decoded)) {
    throw invalidImport('commit block must be an object');
  }
  if (decoded.version !== 3) {
    throw invalidImport('commit version must be 3');
  }
  if (decoded.did !== did) {
    throw invalidImport('commit DID is not hosted by this PDS');
  }
  if (!Object.prototype.hasOwnProperty.call(decoded, 'data')) {
    throw invalidImport('commit data is required');
  }
  if (!Object.prototype.hasOwnProperty.call(decoded, 'prev')) {
    throw invalidImport('commit prev is required');
  }
  const rev = decoded.rev;
  if (typeof rev !== 'string' || !isValidTid(rev)) {
    throw invalidImport('commit rev must be a valid TID');
  }
  const sig = decoded.sig;
  if (!(sig instanceof Uint8Array) || sig.byteLength === 0) {
    throw invalidImport('commit signature is required');
  }

  return {
    cid: root,
    did,
    version: 3,
    data: validateDagCborCid(asCid(decoded.data, 'commit data'), 'commit data'),
    rev,
    prev: decoded.prev === null
      ? null
      : validateDagCborCid(asCid(decoded.prev, 'commit prev'), 'commit prev'),
    sig,
  };
}

async function verifyImportedCommitSignature(env: Env, commit: ImportedCommit): Promise<void> {
  const didKey = await resolveVerificationDidKey(env, commit.did);
  if (!didKey) {
    throw invalidImport('could not resolve repo signing key for commit verification');
  }
  let ok = false;
  try {
    ok = await verifyCommit({
      did: commit.did,
      version: commit.version,
      data: commit.data,
      rev: commit.rev,
      prev: commit.prev,
      sig: commit.sig,
    }, didKey);
  } catch {
    ok = false;
  }
  if (!ok) {
    throw invalidImport('commit signature is invalid');
  }
}

async function resolveVerificationDidKey(env: Env, did: string): Promise<string | null> {
  const fromDidDocument = await resolveDidDocumentAtprotoKey(did);
  if (fromDidDocument) return fromDidDocument;
  if (!isLocalVerificationFallbackDid(did)) return null;

  const privateKey = (await resolveSecret((env as any).REPO_SIGNING_KEY))?.trim();
  if (!privateKey) return null;
  try {
    const { Secp256k1Keypair } = await import('@atproto/crypto');
    const keypair = /^[0-9a-fA-F]{64}$/.test(privateKey)
      ? await Secp256k1Keypair.import(privateKey)
      : await Secp256k1Keypair.import(base64ToBytes(privateKey));
    return keypair.did();
  } catch {
    return null;
  }
}

function isLocalVerificationFallbackDid(did: string): boolean {
  return did.startsWith('did:example:') ||
    did.startsWith('did:localhost:') ||
    did.startsWith('did:dev:');
}

async function resolveDidDocumentAtprotoKey(did: string): Promise<string | null> {
  try {
    const url = didDocumentUrl(did);
    if (!url) return null;

    const response = await fetch(url, { headers: { Accept: 'application/json' } });
    if (!response.ok) return null;
    return parseDidDocumentAtprotoKey(did, await response.json());
  } catch {
    return null;
  }
}

function didDocumentUrl(did: string): string | null {
  if (did.startsWith('did:web:')) {
    const suffix = did.slice('did:web:'.length);
    const parts = suffix.split(':').map((segment) => {
      try {
        return decodeURIComponent(segment);
      } catch {
        return '';
      }
    });
    const host = parts.shift();
    if (!host || parts.some((part) => part.length === 0)) return null;
    return parts.length === 0
      ? `https://${host}/.well-known/did.json`
      : `https://${host}/${parts.join('/')}/did.json`;
  }
  if (did.startsWith('did:plc:')) {
    return `https://plc.directory/${did}`;
  }
  return null;
}

function parseDidDocumentAtprotoKey(did: string, value: unknown): string | null {
  if (!isPlainObject(value) || value.id !== did) return null;
  const methods = Array.isArray(value.verificationMethod)
    ? value.verificationMethod
    : [];
  const validIds = new Set([`${did}#atproto`, '#atproto']);
  for (const method of methods) {
    if (!isPlainObject(method)) continue;
    if (typeof method.id !== 'string' || !validIds.has(method.id)) continue;
    if (method.controller !== did) continue;
    if (method.type !== 'Multikey') continue;
    if (typeof method.publicKeyMultibase !== 'string' || method.publicKeyMultibase.length === 0) {
      continue;
    }
    return `did:key:${method.publicKeyMultibase}`;
  }
  return null;
}

async function walkAndVerifyRecords(
  blocksByCid: Map<string, CarBlock>,
  commit: ImportedCommit,
): Promise<{ records: ImportedRecord[]; reachableMstCids: Set<string> }> {
  const reachableMstCids = await collectReachableMstCids(blocksByCid, commit.data);
  const blockBytes = new Map<string, Uint8Array>();
  for (const [cid, block] of blocksByCid) blockBytes.set(cid, block.bytes);

  let leaves;
  try {
    leaves = await MST.load(new MemoryBlockstore(blockBytes), commit.data).list();
  } catch (error) {
    throw invalidImport('repository MST is incomplete or invalid');
  }

  const records: ImportedRecord[] = [];
  const seen = new Set<string>();
  for (const leaf of leaves) {
    const path = leaf.key;
    if (seen.has(path)) throw invalidImport(`duplicate record path: ${path}`);
    seen.add(path);

    const { collection, rkey } = validateRecordPath(path);
    const recordBlock = blocksByCid.get(leaf.value.toString());
    if (!recordBlock) {
      throw invalidImport(`missing record block: ${leaf.value.toString()}`);
    }
    await validateDagCborBlock(recordBlock);

    let decoded: unknown;
    try {
      decoded = dagCbor.decode(recordBlock.bytes);
    } catch {
      throw invalidImport(`record block is not valid dag-cbor: ${path}`);
    }
    let record: Record<string, unknown>;
    try {
      record = validateRawRecord(collection, ipldToJson(decoded), {
        allowLegacyBlobObjects: true,
      });
    } catch (error) {
      throw invalidImport(error instanceof Error ? error.message : `invalid record: ${path}`);
    }
    const uri = `at://${commit.did}/${path}`;
    records.push({
      path,
      uri,
      cid: leaf.value,
      record,
      json: JSON.stringify(record),
    });
  }

  return {
    records: records.sort((a, b) => a.path.localeCompare(b.path)),
    reachableMstCids,
  };
}

async function collectReachableMstCids(
  blocksByCid: Map<string, CarBlock>,
  root: CID,
): Promise<Set<string>> {
  const reachable = new Set<string>();
  const pending = [root];
  while (pending.length > 0) {
    const cid = pending.pop()!;
    const cidString = cid.toString();
    if (reachable.has(cidString)) continue;
    const block = blocksByCid.get(cidString);
    if (!block) throw invalidImport(`missing MST block: ${cidString}`);
    await validateDagCborBlock(block);
    reachable.add(cidString);

    let node: unknown;
    try {
      node = dagCbor.decode(block.bytes);
    } catch {
      throw invalidImport(`MST block is not valid dag-cbor: ${cidString}`);
    }
    if (!isPlainObject(node) || !Array.isArray(node.e)) {
      throw invalidImport(`invalid MST node: ${cidString}`);
    }
    const left = optionalCid(node.l, 'MST left subtree');
    if (left) pending.push(left);
    for (const entry of node.e) {
      if (!isPlainObject(entry)) throw invalidImport(`invalid MST entry: ${cidString}`);
      if (!Number.isInteger(entry.p) || Number(entry.p) < 0) {
        throw invalidImport(`invalid MST entry prefix length: ${cidString}`);
      }
      if (!(entry.k instanceof Uint8Array)) {
        throw invalidImport(`invalid MST entry key bytes: ${cidString}`);
      }
      asCid(entry.v, 'MST entry value');
      const right = optionalCid(entry.t, 'MST right subtree');
      if (right) pending.push(right);
    }
  }
  return reachable;
}

async function verifyCanonicalMst(root: CID, records: ImportedRecord[]): Promise<void> {
  let rebuilt = await MST.create(new MemoryBlockstore(new Map<string, Uint8Array>()), []);
  for (const record of records) {
    try {
      rebuilt = await rebuilt.add(record.path, record.cid);
    } catch (error) {
      throw invalidImport('repository MST could not be rebuilt');
    }
  }
  const rebuiltRoot = await rebuilt.getPointer();
  if (!rebuiltRoot.equals(root)) {
    throw invalidImport('repository MST root does not match indexed records');
  }
}

function collectBlocksToStore(
  blocksByCid: Map<string, CarBlock>,
  commit: ImportedCommit,
  records: ImportedRecord[],
  reachableMstCids: Set<string>,
): CarBlock[] {
  const cids = new Set<string>([
    commit.cid.toString(),
    ...reachableMstCids,
    ...records.map((record) => record.cid.toString()),
  ]);
  return Array.from(cids, (cid) => {
    const block = blocksByCid.get(cid);
    if (!block) throw invalidImport(`missing reachable block: ${cid}`);
    return block;
  });
}

async function applyImportedRepo(env: Env, did: string, imported: ImportedRepo): Promise<void> {
  const existing = await env.ALTERAN_DB.prepare(
    'SELECT 1 FROM repo_root WHERE did = ? LIMIT 1',
  ).bind(did).first();
  if (existing) {
    throw new RepoImportError('InvalidRequest', 'repo already exists for this DID', 409);
  }

  const guard: CommitGuard = {
    did,
    commitCid: imported.commit.cid.toString(),
    rev: imported.commit.rev,
  };
  const statements: D1PreparedStatement[] = [
    env.ALTERAN_DB.prepare(
      `INSERT INTO repo_root (did, commit_cid, rev)
       SELECT ?, ?, ?
       WHERE NOT EXISTS (
         SELECT 1 FROM repo_root WHERE did = ?
       )`,
    ).bind(did, guard.commitCid, guard.rev, did),
    ...blockstorePutStatements(env, imported.blocksToStore, guard),
  ];

  for (const record of imported.records) {
    statements.push(
      ...putRecordStatements(env, {
        uri: record.uri,
        did,
        cid: record.cid.toString(),
        json: record.json,
      }, guard),
    );
    statements.push(
      ...setRecordBlobUsageStatements(
        env,
        did,
        record.uri,
        await resolveAvailableBlobKeys(env, did, record.record),
        guard,
        record.cid.toString(),
      ),
    );
  }

  statements.push(
    env.ALTERAN_DB.prepare(
      `INSERT INTO commit_log (cid, rev, data, sig, ts)
       SELECT ?, ?, ?, ?, ?
       WHERE EXISTS (
         SELECT 1 FROM repo_root WHERE did = ? AND commit_cid = ?
       )`,
    ).bind(
      guard.commitCid,
      guard.rev,
      JSON.stringify({
        did: imported.commit.did,
        version: imported.commit.version,
        data: imported.commit.data.toString(),
        rev: imported.commit.rev,
        prev: imported.commit.prev?.toString() ?? null,
      }),
      bytesToBase64(imported.commit.sig),
      Date.now(),
      did,
      guard.commitCid,
    ),
  );

  let results: unknown[];
  try {
    results = await env.ALTERAN_DB.batch(statements);
  } catch {
    throw new RepoImportError('InternalServerError', 'Failed to import repo', 500);
  }
  if (changedRows(results[0]) !== 1) {
    throw new RepoImportError('InvalidRequest', 'repo already exists for this DID', 409);
  }
}

function blockstorePutStatements(
  env: Env,
  blocks: CarBlock[],
  guard: CommitGuard,
): D1PreparedStatement[] {
  const deduped = new Map<string, Uint8Array>();
  for (const block of blocks) {
    deduped.set(block.cid.toString(), block.bytes);
  }
  return Array.from(deduped, ([cid, bytes]) =>
    env.ALTERAN_DB.prepare(
      `INSERT OR REPLACE INTO blockstore (cid, bytes)
       SELECT ?, ?
       WHERE EXISTS (
         SELECT 1 FROM repo_root WHERE did = ? AND commit_cid = ?
       )`,
    ).bind(cid, bytesToBase64(bytes), guard.did, guard.commitCid),
  );
}

async function resolveAvailableBlobKeys(
  env: Env,
  did: string,
  record: Record<string, unknown>,
): Promise<string[]> {
  const keys = new Set<string>();
  for (const blob of collectImportBlobRefs(record)) {
    const row = await env.ALTERAN_DB.prepare(
      `SELECT key, mime, size
       FROM blob
       WHERE did = ?
         AND cid = ?
         AND takedown_ref IS NULL
       LIMIT 1`,
    ).bind(did, blob.cid).first<{ key: string; mime: string; size: number }>();
    if (!row) continue;
    if (row.mime !== blob.mimeType) continue;
    if (blob.size !== null && Number(row.size) !== blob.size) continue;
    const object = typeof (env.ALTERAN_BLOBS as any).head === 'function'
      ? await (env.ALTERAN_BLOBS as any).head(row.key)
      : await env.ALTERAN_BLOBS.get(row.key);
    if (object) keys.add(row.key);
  }
  return Array.from(keys);
}

function collectImportBlobRefs(value: Record<string, unknown>): ImportedBlobRef[] {
  const refs: ImportedBlobRef[] = [];
  collectBlobRefs(value, refs);
  for (const legacy of extractBskyLegacyBlobRefs(value)) {
    refs.push({ ...legacy, size: null });
  }
  return refs;
}

function collectBlobRefs(
  value: unknown,
  refs: ImportedBlobRef[],
): void {
  if (!value || typeof value !== 'object') return;
  if (Array.isArray(value)) {
    for (const child of value) collectBlobRefs(child, refs);
    return;
  }
  const obj = value as Record<string, unknown>;
  if (obj.$type === 'blob') {
    const ref = obj.ref;
    const cid = isPlainObject(ref) ? ref.$link : undefined;
    if (
      typeof cid === 'string' &&
      typeof obj.mimeType === 'string' &&
      typeof obj.size === 'number'
    ) {
      refs.push({ cid, mimeType: obj.mimeType, size: obj.size });
    }
    return;
  }
  for (const child of Object.values(obj)) collectBlobRefs(child, refs);
}

function validateRecordPath(path: string): { collection: string; rkey: string } {
  const parts = path.split('/');
  if (parts.length !== 2) throw invalidImport(`invalid record path: ${path}`);
  const [collection, rkey] = parts;
  if (!isValidNsid(collection)) throw invalidImport(`invalid collection in record path: ${path}`);
  if (!isValidRecordKey(rkey)) throw invalidImport(`invalid rkey in record path: ${path}`);
  return { collection, rkey };
}

function optionalCid(value: unknown, field: string): CID | null {
  if (value === null || value === undefined) return null;
  return asCid(value, field);
}

function ipldToJson(value: unknown): unknown {
  const cid = CID.asCID(value);
  if (cid) return { $link: cid.toString() };
  if (value instanceof Uint8Array) return { $bytes: bytesToBase64(value) };
  if (Array.isArray(value)) return value.map(ipldToJson);
  if (!value || typeof value !== 'object') return value;
  const converted: Record<string, unknown> = {};
  for (const [key, child] of Object.entries(value)) {
    converted[key] = ipldToJson(child);
  }
  return converted;
}

function asCid(value: unknown, field: string): CID {
  const cid = CID.asCID(value);
  if (cid) return cid;
  if (typeof value === 'string') {
    try {
      return CID.parse(value);
    } catch {
      // Fall through to the uniform error below.
    }
  }
  throw invalidImport(`${field} must be a CID`);
}

function validateDagCborCid(cid: CID, field: string): CID {
  if (cid.version !== 1 || cid.code !== dagCbor.code) {
    throw invalidImport(`${field} must be a CIDv1 dag-cbor link`);
  }
  if (cid.multihash.code !== 0x12 || cid.multihash.digest.byteLength !== 32) {
    throw invalidImport(`${field} must use a SHA-256 multihash`);
  }
  return cid;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

function base64ToBytes(value: string): Uint8Array {
  const bin = atob(value.replace(/\s+/g, ''));
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  for (let i = 0; i < a.byteLength; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function changedRows(result: unknown): number {
  const meta = (result as { meta?: Record<string, unknown> } | undefined)?.meta;
  const changes = meta?.changes ?? meta?.rows_written ?? meta?.rowsWritten;
  return typeof changes === 'number' ? changes : 0;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function invalidImport(message: string): RepoImportError {
  return new RepoImportError('InvalidRequest', message, 400);
}
