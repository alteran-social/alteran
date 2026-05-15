#!/usr/bin/env -S deno run -A
/**
 * Repair drift between the `record` table and the MST by replaying every
 * orphaned record (present in `record`, absent in MST) back through the
 * PDS via `com.atproto.repo.applyWrites`. Each batch produces a real,
 * signed commit and a firehose `#commit` event, so AppViews stay in sync.
 *
 * Prereqs:
 *   - The PDS must be reachable at --endpoint (default: https://rawkode.dev).
 *   - You need a working primary password or privileged app password.
 *
 * Run from the rawkode.dev (or wherever your wrangler.jsonc + env.cue live):
 *
 *   cuenv -e production exec deno run -A \
 *     /Users/rawkode/Code/src/github.com/alteran-social/alteran/scripts/repair-mst-from-record-table.ts \
 *     --binding rawkode-dev-pds \
 *     --identifier rawkode.dev \
 *     --password "$USER_PASSWORD" \
 *     --collection app.bsky.graph.follow \
 *     --dry-run
 *
 * Drop --dry-run once you've reviewed the plan to actually apply.
 *
 * Flags:
 *   --endpoint <url>           Default: https://${PDS_HOSTNAME} env, else https://rawkode.dev
 *   --identifier <handle>      Default: $PDS_HANDLE
 *   --password <password>      Default: $USER_PASSWORD (primary or privileged app password)
 *   --collection <nsid>        Default: app.bsky.graph.follow. "*" means all collections.
 *   --binding <name>           D1 binding/db name. Default: alteran.
 *   --local                    Use local D1 instead of remote.
 *   --batch-size <n>           Default: 50. Each batch costs (n) writes against the rate
 *                              limit, which is 60/min by default (PDS_RATE_LIMIT_PER_MIN).
 *   --sleep-ms <n>             Pause between batches. Default: 65000 (just over a minute).
 *   --dry-run                  Print the plan; do not POST anything.
 *   --did <did>                Override DID for record-table lookup.
 */

import * as dagCbor from '@ipld/dag-cbor';
import { CID } from 'multiformats/cid';
import * as uint8arrays from 'uint8arrays';

type Args = {
  endpoint: string;
  identifier: string;
  password: string;
  collection: string;
  binding: string;
  remote: boolean;
  batchSize: number;
  sleepMs: number;
  dryRun: boolean;
  did?: string;
};

function parseArgs(): Args {
  const args = Deno.args;
  const get = (name: string): string | undefined => {
    const index = args.findIndex((a) => a === name || a.startsWith(`${name}=`));
    if (index === -1) return undefined;
    const value = args[index];
    if (value.includes('=')) return value.split('=').slice(1).join('=');
    return args[index + 1];
  };
  const env = Deno.env;
  const hostname = env.get('PDS_HOSTNAME');
  return {
    endpoint: get('--endpoint') ?? (hostname ? `https://${hostname}` : 'https://rawkode.dev'),
    identifier: get('--identifier') ?? env.get('PDS_HANDLE') ?? '',
    password: get('--password') ?? env.get('USER_PASSWORD') ?? '',
    collection: get('--collection') ?? 'app.bsky.graph.follow',
    binding: get('--binding') ?? 'alteran',
    remote: !args.includes('--local'),
    batchSize: Number(get('--batch-size') ?? '50'),
    sleepMs: Number(get('--sleep-ms') ?? '65000'),
    dryRun: args.includes('--dry-run'),
    did: get('--did'),
  };
}

type D1Row = Record<string, unknown>;

async function d1Query(binding: string, remote: boolean, sql: string): Promise<D1Row[]> {
  const command = new Deno.Command('deno', {
    args: [
      'run',
      '-A',
      'npm:wrangler@4.91.0',
      'd1',
      'execute',
      binding,
      remote ? '--remote' : '--local',
      '--json',
      '--command',
      sql,
    ],
    stdout: 'piped',
    stderr: 'piped',
  });
  const result = await command.output();
  const stdout = new TextDecoder().decode(result.stdout);
  if (!result.success) {
    const stderr = new TextDecoder().decode(result.stderr);
    throw new Error(`wrangler d1 execute failed (exit ${result.code}). stderr:\n${stderr}\nstdout:\n${stdout}`);
  }
  const parsed = JSON.parse(stdout);
  const entry = Array.isArray(parsed) ? parsed[0] : parsed;
  const results: D1Row[] = entry?.results ?? entry?.result?.results ?? entry?.result?.[0]?.results ?? [];
  return results;
}

function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

function asCid(value: unknown): CID | null {
  if (value === null || value === undefined) return null;
  const cid = CID.asCID(value as object);
  if (cid) return cid;
  if (typeof value === 'string') {
    try {
      return CID.parse(value);
    } catch {
      return null;
    }
  }
  return null;
}

type MstNode = {
  l: unknown;
  e: Array<{ p: number; k: Uint8Array; v: unknown; t: unknown }>;
};

async function fetchBlocks(
  binding: string,
  remote: boolean,
  cids: string[],
): Promise<Map<string, Uint8Array>> {
  const out = new Map<string, Uint8Array>();
  const BATCH = 40;
  for (let i = 0; i < cids.length; i += BATCH) {
    const chunk = cids.slice(i, i + BATCH);
    const inList = chunk.map((c) => `'${c.replace(/'/g, "''")}'`).join(',');
    const rows = await d1Query(
      binding,
      remote,
      `SELECT cid, bytes FROM blockstore WHERE cid IN (${inList})`,
    );
    for (const row of rows) {
      const cidStr = String(row.cid);
      const base64 = row.bytes as string | null;
      if (base64) out.set(cidStr, base64ToBytes(base64));
    }
  }
  return out;
}

async function loadMstRoot(binding: string, remote: boolean): Promise<{ did: string; commitCid: string; mstRoot: CID }> {
  const rootRows = await d1Query(binding, remote, `SELECT did, commit_cid AS commitCid FROM repo_root LIMIT 1`);
  if (rootRows.length === 0) throw new Error('repo_root is empty');
  const did = String(rootRows[0].did);
  const commitCid = String(rootRows[0].commitCid);

  const commitLogRows = await d1Query(
    binding,
    remote,
    `SELECT data FROM commit_log WHERE cid = '${commitCid.replace(/'/g, "''")}' LIMIT 1`,
  );
  let mstRoot: CID | null = null;
  if (commitLogRows.length > 0) {
    const commit = JSON.parse(String(commitLogRows[0].data)) as { data: unknown };
    mstRoot = asCid(commit.data);
  } else {
    const blocks = await fetchBlocks(binding, remote, [commitCid]);
    const bytes = blocks.get(commitCid);
    if (bytes) {
      const commit = dagCbor.decode(bytes) as { data: unknown };
      mstRoot = asCid(commit.data);
    }
  }
  if (!mstRoot) throw new Error(`Could not resolve MST root for commit ${commitCid}`);
  return { did, commitCid, mstRoot };
}

async function walkMst(binding: string, remote: boolean, rootCid: CID): Promise<Set<string>> {
  const keys = new Set<string>();
  let frontier: string[] = [rootCid.toString()];
  const visited = new Set<string>();

  while (frontier.length > 0) {
    const blocks = await fetchBlocks(binding, remote, frontier);
    const nextFrontier: string[] = [];

    for (const cidStr of frontier) {
      if (visited.has(cidStr)) continue;
      visited.add(cidStr);
      const bytes = blocks.get(cidStr);
      if (!bytes) continue;
      let node: MstNode;
      try {
        node = dagCbor.decode(bytes) as MstNode;
      } catch {
        continue;
      }
      const left = asCid(node.l);
      if (left) nextFrontier.push(left.toString());
      let lastKey = '';
      for (const entry of node.e ?? []) {
        const suffix = uint8arrays.toString(entry.k, 'ascii');
        const key = lastKey.slice(0, entry.p) + suffix;
        lastKey = key;
        keys.add(key);
        const childTree = asCid(entry.t);
        if (childTree) nextFrontier.push(childTree.toString());
      }
    }
    frontier = nextFrontier;
  }
  return keys;
}

async function fetchOrphanRecords(
  binding: string,
  remote: boolean,
  did: string,
  collectionFilter: string | null,
  mstKeys: Set<string>,
): Promise<Array<{ collection: string; rkey: string; value: unknown }>> {
  const escDid = did.replace(/'/g, "''");
  let where = `did = '${escDid}'`;
  if (collectionFilter) {
    const prefix = `at://${did}/${collectionFilter}/`;
    const upper = prefix.slice(0, -1) + String.fromCharCode(prefix.charCodeAt(prefix.length - 1) + 1);
    where += ` AND uri >= '${prefix.replace(/'/g, "''")}' AND uri < '${upper.replace(/'/g, "''")}'`;
  }

  const orphans: Array<{ collection: string; rkey: string; value: unknown }> = [];
  const PAGE = 500;
  const recordPrefix = `at://${did}/`;
  let after = '';
  while (true) {
    const cursorClause = after ? ` AND uri > '${after.replace(/'/g, "''")}'` : '';
    const sql = `SELECT uri, json FROM record WHERE ${where}${cursorClause} ORDER BY uri LIMIT ${PAGE}`;
    const rows = await d1Query(binding, remote, sql);
    if (rows.length === 0) break;
    for (const row of rows) {
      const uri = String(row.uri);
      if (!uri.startsWith(recordPrefix)) continue;
      const key = uri.slice(recordPrefix.length);
      if (collectionFilter && !key.startsWith(`${collectionFilter}/`)) continue;
      if (mstKeys.has(key)) continue;
      const slashIndex = key.indexOf('/');
      if (slashIndex === -1) continue;
      const collection = key.slice(0, slashIndex);
      const rkey = key.slice(slashIndex + 1);
      let value: unknown;
      try {
        value = JSON.parse(String(row.json));
      } catch (error) {
        console.warn(`[WARN] Could not parse JSON for ${uri}: ${(error as Error).message}`);
        continue;
      }
      orphans.push({ collection, rkey, value });
    }
    after = String(rows[rows.length - 1].uri);
    if (rows.length < PAGE) break;
  }
  return orphans;
}

type Session = { accessJwt: string; refreshJwt: string; did: string; handle: string };

async function login(endpoint: string, identifier: string, password: string): Promise<Session> {
  const response = await fetch(`${endpoint}/xrpc/com.atproto.server.createSession`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ identifier, password }),
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`createSession failed (${response.status}): ${text}`);
  }
  return (await response.json()) as Session;
}

async function applyWritesBatch(
  endpoint: string,
  session: Session,
  repo: string,
  batch: Array<{ collection: string; rkey: string; value: unknown }>,
): Promise<void> {
  const writes = batch.map((entry) => ({
    $type: 'com.atproto.repo.applyWrites#create',
    collection: entry.collection,
    rkey: entry.rkey,
    value: entry.value,
  }));
  const response = await fetch(`${endpoint}/xrpc/com.atproto.repo.applyWrites`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${session.accessJwt}`,
    },
    body: JSON.stringify({ repo, writes, validate: false }),
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`applyWrites failed (${response.status}): ${text}`);
  }
}

async function main() {
  const args = parseArgs();

  if (!args.dryRun) {
    if (!args.identifier) throw new Error('Missing --identifier (or $PDS_HANDLE)');
    if (!args.password) throw new Error('Missing --password (or $USER_PASSWORD)');
  }

  console.log(`[INFO] Endpoint: ${args.endpoint}`);
  console.log(`[INFO] Identifier: ${args.identifier || '(dry-run, not required)'}`);
  console.log(`[INFO] Collection: ${args.collection === '*' ? '<all>' : args.collection}`);
  console.log(`[INFO] D1 binding: ${args.binding} (${args.remote ? 'remote' : 'local'})`);
  console.log(`[INFO] Batch size: ${args.batchSize}`);
  console.log(`[INFO] Dry run: ${args.dryRun}`);

  const { did, mstRoot } = await loadMstRoot(args.binding, args.remote);
  const effectiveDid = args.did ?? did;
  console.log(`[INFO] DID: ${effectiveDid}`);
  console.log(`[INFO] MST root: ${mstRoot.toString()}`);
  console.log('[INFO] Walking MST...');
  const mstKeys = await walkMst(args.binding, args.remote, mstRoot);
  console.log(`[INFO] MST keys present: ${mstKeys.size}`);

  const collectionFilter = args.collection === '*' ? null : args.collection;
  console.log('[INFO] Scanning record table for orphans...');
  const orphans = await fetchOrphanRecords(args.binding, args.remote, effectiveDid, collectionFilter, mstKeys);
  console.log(`[INFO] Orphan records to replay: ${orphans.length}`);

  if (orphans.length === 0) {
    console.log('[OK] Nothing to do.');
    return;
  }

  if (args.dryRun) {
    console.log('');
    console.log('=== DRY RUN: first 10 orphans that would be replayed ===');
    for (const orphan of orphans.slice(0, 10)) {
      const preview = JSON.stringify(orphan.value);
      const truncated = preview.length > 140 ? `${preview.slice(0, 140)}...` : preview;
      console.log(`  ${orphan.collection}/${orphan.rkey}  ${truncated}`);
    }
    if (orphans.length > 10) console.log(`  ... and ${orphans.length - 10} more`);
    console.log('');
    console.log(`[OK] Dry run. Re-run without --dry-run to POST ${Math.ceil(orphans.length / args.batchSize)} applyWrites batches.`);
    return;
  }

  console.log('[INFO] Logging in...');
  const session = await login(args.endpoint, args.identifier, args.password);
  console.log(`[INFO] Authenticated as ${session.handle} (${session.did})`);
  if (session.did !== effectiveDid) {
    throw new Error(`Logged-in DID (${session.did}) does not match repo DID (${effectiveDid})`);
  }

  const batches = Math.ceil(orphans.length / args.batchSize);
  for (let i = 0; i < orphans.length; i += args.batchSize) {
    const batch = orphans.slice(i, i + args.batchSize);
    const batchIndex = Math.floor(i / args.batchSize) + 1;
    console.log(`[INFO] Applying batch ${batchIndex}/${batches} (${batch.length} writes)...`);
    await applyWritesBatch(args.endpoint, session, effectiveDid, batch);
    console.log(`[OK] Batch ${batchIndex} applied.`);
    if (batchIndex < batches && args.sleepMs > 0) {
      console.log(`[INFO] Sleeping ${args.sleepMs}ms to respect PDS_RATE_LIMIT_PER_MIN...`);
      await new Promise((resolve) => setTimeout(resolve, args.sleepMs));
    }
  }

  console.log(`[DONE] Replayed ${orphans.length} orphan records into the MST.`);
}

if (import.meta.main) {
  main().catch((error) => {
    console.error('[FATAL]', error);
    Deno.exit(1);
  });
}
