#!/usr/bin/env -S deno run -A
export {};
/**
 * Test com.atproto.server.createSession against your PDS.
 *
 * Usage:
 *   bun run scripts/test-create-session.ts --host your-pds.example.com \
 *     [--identifier user] [--password <USER_PASSWORD>] [--json] [--print-tokens]
 *
 * Notes:
 * - If you omit --identifier, it defaults to "user" (single-user setups)
 * - If you omit --password, it tries $USER_PASSWORD then $PDS_PASSWORD
 * - --host accepts either a bare hostname or a full URL
 */

// Arg parser: supports "--key=value" and "--key value" and boolean switches
function parseArgs(argv: string[]): Map<string, string | boolean> {
  const out = new Map<string, string | boolean>();
  let i = 0;
  // If user invoked via "bun run script -- ...", skip until after the first "--"
  const idx = argv.indexOf('--');
  if (idx !== -1) i = idx + 1;
  for (; i < argv.length; i++) {
    const token = argv[i];
    if (!token.startsWith('--')) continue;
    const eq = token.indexOf('=');
    if (eq !== -1) {
      const k = token.slice(2, eq);
      const v = token.slice(eq + 1);
      out.set(`--${k}`, v);
      continue;
    }
    const k = token;
    const next = argv[i + 1];
    if (next && !next.startsWith('--')) {
      out.set(k, next);
      i++; // consume value
    } else {
      out.set(k, true);
    }
  }
  return out;
}

const args = parseArgs(process.argv.slice(2));

function getFlag(name: string, fallback?: string): string | undefined {
  const v = args.get(`--${name}`);
  if (v === undefined) return fallback;
  if (typeof v === 'boolean') return fallback;
  return v;
}

function hasFlag(name: string): boolean {
  return args.get(`--${name}`) === true;
}

function normalizeBase(input: string): string {
  const trimmed = input.trim();
  if (!trimmed) return '';
  const noSlash = trimmed.replace(/\/$/, '');
  if (/^https?:\/\//i.test(noSlash)) return noSlash;
  return `https://${noSlash}`;
}

async function main() {
  const hostArg = getFlag('host') || process.env.PDS_HOSTNAME || '';
  const base = normalizeBase(hostArg);
  if (!base) {
    console.error('Missing --host. Example: --host your-pds.example.com or --host=https://your-pds.example.com');
    process.exit(2);
  }

  const identifier = getFlag('identifier') || process.env.PDS_HANDLE || 'user';
  const password =
    getFlag('password') || process.env.USER_PASSWORD || process.env.PDS_PASSWORD || '';

  if (!password) {
    console.error('Missing password. Pass --password <value> or --password=<value>, or set USER_PASSWORD.');
    process.exit(2);
  }

  const url = `${base}/xrpc/com.atproto.server.createSession`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ identifier, password }),
  });

  const text = await res.text();
  let data: any;
  try {
    data = JSON.parse(text);
  } catch {
    data = text;
  }

  if (!res.ok) {
    console.error(`createSession ${res.status} ${res.statusText}`);
    console.error(typeof data === 'string' ? data : JSON.stringify(data, null, 2));
    process.exit(1);
  }

  if (hasFlag('json')) {
    console.log(JSON.stringify(data, null, 2));
    return;
  }

  const access = data?.accessJwt ? String(data.accessJwt) : '';
  const refresh = data?.refreshJwt ? String(data.refreshJwt) : '';
  const short = (t: string) => (t ? `${t.slice(0, 16)}...` : '');
  const printTokens = hasFlag('print-tokens');

  console.log(`OK: did=${data.did} handle=${data.handle}`);
  if (printTokens) {
    console.log(`accessJwt: ${access}`);
    console.log(`refreshJwt: ${refresh}`);
  } else {
    console.log(`accessJwt: ${short(access)}`);
    console.log(`refreshJwt: ${short(refresh)}`);
    console.log('(use --print-tokens to show full tokens)');
  }
}

main().catch((e) => {
  console.error(e?.stack || String(e));
  process.exit(1);
});
