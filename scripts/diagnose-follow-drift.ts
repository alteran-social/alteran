#!/usr/bin/env -S deno run -A
/**
 * Diagnose drift between the MST and the `record` table for a single collection
 * (default: app.bsky.graph.follow).
 *
 * The unfollow-stuck symptom looks like this: bsky.app calls deleteRecord with
 * an rkey it got from the AppView (or from this PDS via the listRecords
 * fallback). Our handler checks the MST, finds nothing at that key, returns
 * 200 with `{}`, and never broadcasts a firehose event — so the AppView keeps
 * the follow forever. That happens when the `record` table contains rows whose
 * keys are absent from the MST.
 *
 * Run with prod creds loaded:
 *   cuenv -e production exec deno run -A scripts/diagnose-follow-drift.ts
 *
 * Flags:
 *   --collection <nsid>   Default: app.bsky.graph.follow. Use "*" for all.
 *   --did <did>           Override DID; default reads repo_root (single-user).
 *   --binding <name>      Default: alteran (matches wrangler.jsonc).
 *   --local               Query local D1 instead of remote.
 *   --limit <n>           Cap printed examples per category (default 20).
 */

import * as dagCbor from '@ipld/dag-cbor';
import { CID } from 'multiformats/cid';
import * as uint8arrays from 'uint8arrays';

type Args = {
  collection: string;
  did?: string;
  binding: string;
  remote: boolean;
  limit: number;
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
  return {
    collection: get('--collection') ?? 'app.bsky.graph.follow',
    did: get('--did'),
    binding: get('--binding') ?? 'alteran',
    remote: !args.includes('--local'),
    limit: Number(get('--limit') ?? '20'),
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
    throw new Error(
      `wrangler d1 execute failed (exit ${result.code}). stderr:\n${stderr}\nstdout:\n${stdout}`,
    );
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

async function walkMst(
  binding: string,
  remote: boolean,
  rootCid: CID,
): Promise<Map<string, string>> {
  const keys = new Map<string, string>();
  let frontier: string[] = [rootCid.toString()];
  const visited = new Set<string>();

  while (frontier.length > 0) {
    const blocks = await fetchBlocks(binding, remote, frontier);
    const nextFrontier: string[] = [];

    for (const cidStr of frontier) {
      if (visited.has(cidStr)) continue;
      visited.add(cidStr);
      const bytes = blocks.get(cidStr);
      if (!bytes) {
        console.warn(`[WARN] MST node missing from blockstore: ${cidStr}`);
        continue;
      }
      let node: MstNode;
      try {
        node = dagCbor.decode(bytes) as MstNode;
      } catch (error) {
        console.warn(`[WARN] Failed to decode MST node ${cidStr}: ${(error as Error).message}`);
        continue;
      }

      const left = asCid(node.l);
      if (left) nextFrontier.push(left.toString());

      let lastKey = '';
      for (const entry of node.e ?? []) {
        const suffix = uint8arrays.toString(entry.k, 'ascii');
        const key = lastKey.slice(0, entry.p) + suffix;
        lastKey = key;
        const valueCid = asCid(entry.v);
        if (valueCid) keys.set(key, valueCid.toString());
        const childTree = asCid(entry.t);
        if (childTree) nextFrontier.push(childTree.toString());
      }
    }

    frontier = nextFrontier;
  }

  return keys;
}

async function fetchAllRecords(
  binding: string,
  remote: boolean,
  did: string,
  collection: string | null,
): Promise<Array<{ uri: string; cid: string }>> {
  const escDid = did.replace(/'/g, "''");
  let where = `did = '${escDid}'`;
  if (collection) {
    const prefix = `at://${did}/${collection}/`;
    const upper = prefix.slice(0, -1) + String.fromCharCode(prefix.charCodeAt(prefix.length - 1) + 1);
    where += ` AND uri >= '${prefix.replace(/'/g, "''")}' AND uri < '${upper.replace(/'/g, "''")}'`;
  }

  const out: Array<{ uri: string; cid: string }> = [];
  const PAGE = 500;
  let after = '';
  while (true) {
    const cursorClause = after ? ` AND uri > '${after.replace(/'/g, "''")}'` : '';
    const sql = `SELECT uri, cid FROM record WHERE ${where}${cursorClause} ORDER BY uri LIMIT ${PAGE}`;
    const rows = await d1Query(binding, remote, sql);
    if (rows.length === 0) break;
    for (const row of rows) {
      out.push({ uri: String(row.uri), cid: String(row.cid) });
    }
    after = String(rows[rows.length - 1].uri);
    if (rows.length < PAGE) break;
  }
  return out;
}

async function main() {
  const args = parseArgs();
  console.log(`[INFO] Mode: ${args.remote ? 'remote (production D1)' : 'local D1'}`);
  console.log(`[INFO] Binding: ${args.binding}`);
  console.log(`[INFO] Collection filter: ${args.collection === '*' ? '<all>' : args.collection}`);

  let did = args.did;
  if (!did) {
    const rows = await d1Query(
      args.binding,
      args.remote,
      `SELECT did, commit_cid, rev FROM repo_root LIMIT 1`,
    );
    if (rows.length === 0) {
      console.error('[ERROR] repo_root is empty. Pass --did <did> to override.');
      Deno.exit(2);
    }
    did = String(rows[0].did);
  }
  console.log(`[INFO] DID: ${did}`);

  const rootRows = await d1Query(
    args.binding,
    args.remote,
    `SELECT commit_cid AS commitCid, rev FROM repo_root WHERE did = '${did.replace(/'/g, "''")}'`,
  );
  if (rootRows.length === 0) {
    console.error(`[ERROR] No repo_root row for DID ${did}`);
    Deno.exit(2);
  }
  const commitCidStr = String(rootRows[0].commitCid);
  const rev = String(rootRows[0].rev);
  console.log(`[INFO] commit_cid: ${commitCidStr}`);
  console.log(`[INFO] rev: ${rev}`);

  // The runtime reads commits from commit_log (JSON), so this script does too.
  // The commit block in `blockstore` (CBOR) is optional and may be missing on
  // repos imported via CAR before that was fixed up.
  const commitLogRows = await d1Query(
    args.binding,
    args.remote,
    `SELECT data FROM commit_log WHERE cid = '${commitCidStr.replace(/'/g, "''")}' LIMIT 1`,
  );
  let mstRoot: CID | null = null;
  if (commitLogRows.length > 0) {
    const commit = JSON.parse(String(commitLogRows[0].data)) as { data: unknown };
    mstRoot = asCid(commit.data);
    console.log('[INFO] commit source: commit_log (JSON)');
  } else {
    const commitBlocks = await fetchBlocks(args.binding, args.remote, [commitCidStr]);
    const commitBytes = commitBlocks.get(commitCidStr);
    if (commitBytes) {
      const commit = dagCbor.decode(commitBytes) as { data: unknown };
      mstRoot = asCid(commit.data);
      console.log('[INFO] commit source: blockstore (CBOR)');
    }
  }
  if (!mstRoot) {
    console.error(
      `[ERROR] Could not resolve MST root: commit ${commitCidStr} not found in commit_log or blockstore.`,
    );
    Deno.exit(3);
  }
  console.log(`[INFO] MST root: ${mstRoot.toString()}`);
  console.log('[INFO] Walking MST...');
  const mstKeys = await walkMst(args.binding, args.remote, mstRoot);
  console.log(`[INFO] MST keys discovered: ${mstKeys.size}`);

  const collectionFilter = args.collection === '*' ? null : args.collection;
  console.log('[INFO] Loading record table...');
  const records = await fetchAllRecords(args.binding, args.remote, did, collectionFilter);
  console.log(`[INFO] record rows under filter: ${records.length}`);

  const recordKeys = new Map<string, string>();
  const recordPrefix = `at://${did}/`;
  for (const row of records) {
    if (!row.uri.startsWith(recordPrefix)) continue;
    const key = row.uri.slice(recordPrefix.length);
    if (collectionFilter && !key.startsWith(`${collectionFilter}/`)) continue;
    recordKeys.set(key, row.cid);
  }

  const orphansInRecordTable: Array<{ key: string; cid: string }> = [];
  const cidMismatches: Array<{ key: string; recordCid: string; mstCid: string }> = [];
  for (const [key, cid] of recordKeys) {
    const mstCid = mstKeys.get(key);
    if (!mstCid) {
      orphansInRecordTable.push({ key, cid });
    } else if (mstCid !== cid) {
      cidMismatches.push({ key, recordCid: cid, mstCid });
    }
  }

  const orphansInMst: Array<{ key: string; cid: string }> = [];
  for (const [key, cid] of mstKeys) {
    if (collectionFilter && !key.startsWith(`${collectionFilter}/`)) continue;
    if (!recordKeys.has(key)) orphansInMst.push({ key, cid });
  }

  const filterLabel = collectionFilter ?? '<all collections>';
  console.log('');
  console.log(`=== Drift report for ${filterLabel} ===`);
  console.log(`Total in record table: ${recordKeys.size}`);
  console.log(`Total in MST (filtered): ${
    collectionFilter
      ? Array.from(mstKeys.keys()).filter((k) => k.startsWith(`${collectionFilter}/`)).length
      : mstKeys.size
  }`);
  console.log('');
  console.log(`Orphans in record table (record table has it, MST doesn't): ${orphansInRecordTable.length}`);
  console.log('  -> deleteRecord against these rkeys will silently no-op.');
  for (const orphan of orphansInRecordTable.slice(0, args.limit)) {
    console.log(`     ${orphan.key}  (cid=${orphan.cid})`);
  }
  if (orphansInRecordTable.length > args.limit) {
    console.log(`     ... and ${orphansInRecordTable.length - args.limit} more`);
  }
  console.log('');
  console.log(`Orphans in MST (MST has it, record table doesn't): ${orphansInMst.length}`);
  console.log('  -> listRecords from MST returns these but they have no JSON body in `record`.');
  for (const orphan of orphansInMst.slice(0, args.limit)) {
    console.log(`     ${orphan.key}  (cid=${orphan.cid})`);
  }
  if (orphansInMst.length > args.limit) {
    console.log(`     ... and ${orphansInMst.length - args.limit} more`);
  }
  console.log('');
  console.log(`CID mismatches (key in both but CIDs differ): ${cidMismatches.length}`);
  for (const mismatch of cidMismatches.slice(0, args.limit)) {
    console.log(`     ${mismatch.key}`);
    console.log(`        record cid: ${mismatch.recordCid}`);
    console.log(`        mst    cid: ${mismatch.mstCid}`);
  }
  if (cidMismatches.length > args.limit) {
    console.log(`     ... and ${cidMismatches.length - args.limit} more`);
  }

  const drifted = orphansInRecordTable.length + orphansInMst.length + cidMismatches.length;
  console.log('');
  if (drifted === 0) {
    console.log('[OK] No drift detected. The MST and record table agree.');
  } else {
    console.log(`[DRIFT] ${drifted} inconsistencies found.`);
    Deno.exit(1);
  }
}

if (import.meta.main) {
  main().catch((error) => {
    console.error('[FATAL]', error);
    Deno.exit(1);
  });
}
