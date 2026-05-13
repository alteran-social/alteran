import { describe, expect, test } from 'bun:test';
import { mkdtemp, readdir, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import alteran from '../index.js';
import { makeEnv } from './helpers/env';
import { authenticateRequest } from '../src/lib/auth';
import { issueSessionTokens } from '../src/lib/session-tokens';

const did = 'did:example:test';

async function sqliteNames(env: Awaited<ReturnType<typeof makeEnv>>, type: 'table' | 'index') {
  const result = await env.ALTERAN_DB.prepare(
    "SELECT name FROM sqlite_master WHERE type = ? AND name NOT LIKE 'sqlite_%' AND sql IS NOT NULL ORDER BY name"
  )
    .bind(type)
    .all<{ name: string }>();
  return (result.results ?? []).map((row) => row.name);
}

async function withCapturedConsole(fn: () => Promise<void>) {
  const originalLog = console.log;
  const originalError = console.error;
  const logs: unknown[][] = [];
  const errors: unknown[][] = [];

  console.log = (...args: unknown[]) => {
    logs.push(args);
  };
  console.error = (...args: unknown[]) => {
    errors.push(args);
  };

  try {
    await fn();
  } finally {
    console.log = originalLog;
    console.error = originalError;
  }

  return { logs, errors };
}

function ttl(payload: { exp?: number; iat?: number }) {
  expect(typeof payload.exp).toBe('number');
  expect(typeof payload.iat).toBe('number');
  return payload.exp! - payload.iat!;
}

describe('runtime hardening', () => {
  test('migrations produce the exact production table and index set', async () => {
    const env = await makeEnv();

    expect(await sqliteNames(env, 'table')).toEqual([
      'account',
      'account_state',
      'actor_preferences',
      'blob',
      'blob_quota',
      'blob_usage',
      'blockstore',
      'chat_convo',
      'chat_convo_member',
      'commit_log',
      'login_attempts',
      'oauth_session',
      'rate_limit',
      'record',
      'refresh_token',
      'repo_root',
      'secret',
    ]);

    expect(await sqliteNames(env, 'index')).toEqual([
      'account_handle_unique',
      'blob_usage_record_uri_idx',
      'chat_convo_member_did_idx',
      'commit_log_seq_idx',
      'oauth_session_access_jti_idx',
      'oauth_session_client_idx',
      'oauth_session_current_refresh_idx',
      'record_cid_idx',
      'record_did_idx',
      'refresh_token_access_jti_idx',
      'refresh_token_did_idx',
      'refresh_token_oauth_session_idx',
    ]);
  });

  test('production source paths do not create tables at runtime', async () => {
    const root = join(process.cwd(), 'src');
    const files = await sourceFiles(root);
    const offenders: string[] = [];

    for (const file of files) {
      const rel = relative(process.cwd(), file);
      if (rel.startsWith('src/pages/debug/') || rel === 'src/handlers/debug.ts') {
        continue;
      }

      const content = await readFile(file, 'utf8');
      if (/CREATE\s+(TABLE|INDEX)/i.test(content)) {
        offenders.push(rel);
      }
    }

    expect(offenders).toEqual([]);
  });

  test('bearer session tokens honor configured TTLs', async () => {
    const env = await makeEnv({
      PDS_ACCESS_TTL_SEC: '123',
      PDS_REFRESH_TTL_SEC: '456',
    });

    const { accessPayload, refreshPayload } = await issueSessionTokens(env, did);

    expect(ttl(accessPayload)).toBe(123);
    expect(ttl(refreshPayload)).toBe(456);
  });

  test('OAuth public-client tokens use local-spec-safe lifetime caps', async () => {
    const env = await makeEnv({
      PDS_OAUTH_ACCESS_TTL_SEC: '3600',
      PDS_OAUTH_PUBLIC_REFRESH_TTL_SEC: '9999999',
    });

    const { accessPayload, refreshPayload } = await issueSessionTokens(env, did, {
      scope: 'atproto',
      dpopJkt: 'public-client-jkt',
      clientId: 'https://client.example/metadata',
      oauthSessionId: 'oauth-session',
      oauthClientAuthMethod: 'none',
    });

    expect(ttl(accessPayload)).toBe(900);
    expect(ttl(refreshPayload)).toBe(1209600);
  });

  test('OAuth confidential-client tokens honor configured safe lifetimes', async () => {
    const env = await makeEnv({
      PDS_OAUTH_ACCESS_TTL_SEC: '600',
      PDS_OAUTH_CONFIDENTIAL_REFRESH_TTL_SEC: '172800',
    });

    const { accessPayload, refreshPayload } = await issueSessionTokens(env, did, {
      scope: 'atproto',
      dpopJkt: 'confidential-client-jkt',
      clientId: 'https://client.example/metadata',
      oauthSessionId: 'oauth-session',
      oauthClientAuthMethod: 'private_key_jwt',
    });

    expect(ttl(accessPayload)).toBe(600);
    expect(ttl(refreshPayload)).toBe(172800);
  });

  test('bearer authentication does not log token details on success or failure', async () => {
    const env = await makeEnv();
    const { accessJwt } = await issueSessionTokens(env, did);

    const valid = await withCapturedConsole(async () => {
      const auth = await authenticateRequest(
        new Request('https://pds.example/xrpc/com.atproto.server.getSession', {
          headers: { authorization: `Bearer ${accessJwt}` },
        }),
        env,
      );
      expect(auth?.claims.sub).toBe(did);
    });
    expect(valid.logs).toEqual([]);
    expect(valid.errors).toEqual([]);

    const invalid = await withCapturedConsole(async () => {
      const auth = await authenticateRequest(
        new Request('https://pds.example/xrpc/com.atproto.server.getSession', {
          headers: { authorization: 'Bearer not-a-jwt' },
        }),
        env,
      );
      expect(auth).toBeNull();
    });
    expect(invalid.logs).toEqual([]);
    expect(invalid.errors).toEqual([]);
  });
});

describe('package smoke', () => {
  test('integration injects packaged routes and middleware by default', () => {
    const integration = alteran();
    const hooks = integration.hooks as Record<string, Function>;
    const routes: { pattern: string; entrypoint: string }[] = [];
    const middleware: { entrypoint: string; order: string }[] = [];
    const updates: unknown[] = [];

    hooks['astro:config:setup']({
      config: {
        output: 'static',
        root: new URL('file:///tmp/alteran-consumer/'),
        srcDir: new URL('file:///tmp/alteran-consumer/src/'),
        pagesDir: new URL('file:///tmp/alteran-consumer/src/pages/'),
        vite: {},
        adapter: { name: '@astrojs/cloudflare' },
      },
      updateConfig: (update: unknown) => updates.push(update),
      addMiddleware: (entry: { entrypoint: string; order: string }) => middleware.push(entry),
      injectRoute: (route: { pattern: string; entrypoint: string }) => routes.push(route),
      logger: { info: () => {}, warn: () => {} },
    });

    const patterns = routes.map((route) => route.pattern);
    expect(middleware).toHaveLength(1);
    expect(middleware[0]?.order).toBe('pre');
    expect(updates).toContainEqual({ output: 'server' });
    expect(patterns).toContain('/.well-known/atproto-did');
    expect(patterns).toContain('/.well-known/oauth-authorization-server');
    expect(patterns).toContain('/oauth/token');
    expect(patterns).toContain('/xrpc/com.atproto.server.createSession');
    expect(patterns).toContain('/xrpc/com.atproto.repo.applyWrites');
    expect(patterns).toContain('/xrpc/[...nsid]');
    expect(patterns).not.toContain('/debug/db/bootstrap');
  });

  test('npm package contains integration, types, migrations, and route sources', async () => {
    const npmCache = await mkdtemp(join(tmpdir(), 'alteran-npm-cache-'));
    let stdout = '';
    let stderr = '';
    let exitCode = 1;

    try {
      const proc = Bun.spawn(['npm', 'pack', '--dry-run', '--json'], {
        cwd: process.cwd(),
        stdout: 'pipe',
        stderr: 'pipe',
        env: { ...process.env, npm_config_cache: npmCache },
      });
      stdout = await new Response(proc.stdout).text();
      stderr = await new Response(proc.stderr).text();
      exitCode = await proc.exited;
    } finally {
      await rm(npmCache, { recursive: true, force: true });
    }

    expect({ exitCode, stderr }).toMatchObject({ exitCode: 0 });
    const [pack] = JSON.parse(stdout) as [{ files: { path: string }[] }];
    const files = pack.files.map((file) => file.path);

    expect(files).toContain('index.js');
    expect(files).toContain('index.d.ts');
    expect(files).toContain('types/env.d.ts');
    expect(files).toContain('migrations/0010_outstanding_the_stranger.sql');
    expect(files).toContain('src/pages/xrpc/com.atproto.server.createSession.ts');
    expect(files).toContain('src/pages/xrpc/com.atproto.repo.applyWrites.ts');
    expect(files.some((file) => file.startsWith('migrations/') && file.endsWith('.sql'))).toBe(true);
  });
});

async function sourceFiles(dir: string): Promise<string[]> {
  const entries = await readdir(dir, { withFileTypes: true });
  const files: string[] = [];

  for (const entry of entries) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...await sourceFiles(path));
    } else if (entry.isFile() && /\.[cm]?tsx?$/.test(entry.name)) {
      files.push(path);
    }
  }

  return files;
}
