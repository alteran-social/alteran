# Alteran

> [!WARNING]
> This project was built using agentic coding tools and is currently undergoing a systematic review by a human in their spare time. Nobody should use this project as their PDS yet.

Alteran does not yet support AT Protocol Spaces or migration of Spaces data.
See the [Spaces readiness notes](https://github.com/alteran-social/alteran/blob/main/docs/SPACES_READINESS.md) before moving an
account or building against a Spaces-capable PDS.

## Astro Integration

This repository now ships an Astro integration that turns any Cloudflare Worker-backed Astro app into a single-user ATProto Personal Data Server. Install the package (or link it locally), then add the integration to your `astro.config.mjs`:

```bash
npm install @alteran-social/astro
# or, in a Deno project
deno add npm:@alteran-social/astro
```

```ts
import { defineConfig } from 'astro/config';
import cloudflare from '@astrojs/cloudflare';
import alteran from '@alteran-social/astro';

export default defineConfig({
  adapter: cloudflare({ mode: 'advanced' }),
  integrations: [alteran()],
});
```

By default the integration injects all `/xrpc/*` ATProto routes, health/ready checks, and the Cloudflare Worker entrypoint that supplies `locals.env`. Optional flags let you expose the `/debug/*` utilities or keep your own homepage:

```ts
alteran({
  debugRoutes: process.env.NODE_ENV !== 'production',
  includeRootEndpoint: false,
});
```

The integration automatically:
- Resolves all injected routes against the packaged runtime without requiring a Vite alias
- Registers the middleware that applies structured logging and CORS enforcement
- Injects all PDS HTTP endpoints into the host project
- By default, aliases the Cloudflare adapter entrypoint to a wrapper for PDS concerns such as CORS, Sequencer routing, and config validation
- Publishes ambient env typings so `Env` and `App.Locals` are available from TypeScript

Configure the Worker identity, D1, R2 and credentials for the intended deployment.

Provide Alteran's runtime settings as Worker vars or secrets. The credentials
listed in [Configuration](docs/CONFIGURATION.md) also support Secret Store
bindings. Alteran does not use Astro's global env accessor.

### Custom Worker Entrypoint

By default, the integration aliases the Cloudflare adapter's server entrypoints to Alteran's wrapper. Existing aliases are left unchanged. To export additional Durable Objects alongside `Sequencer`, compose Alteran's runtime helpers from `@alteran-social/astro/worker`.

```ts
// src/_worker.ts in your Astro project
import { createPdsFetchHandler, Sequencer } from '@alteran-social/astro/worker';

const fetch = createPdsFetchHandler();

export default { fetch };

// Re-export Sequencer so Wrangler can bind the Durable Object namespace
export { Sequencer };

// Export any additional Durable Objects after this line
export { MyDurableObject } from './worker/my-durable-object';
```

Helpers like `onRequest`, `seed`, and `validateConfigOrThrow` are also exported from `@alteran-social/astro/worker` if you need to build more advanced wrappers (for example, to add request instrumentation before delegating to the PDS handler).

Enable Cloudflare's `nodejs_compat` flag for the request-local Env handoff.
When invoking `onRequest` without the Worker wrapper, set `locals.env` to the
current request's Worker Env; the middleware fails closed if it is absent.
An existing adapter entrypoint alias or custom entrypoint must compose
`createPdsFetchHandler` or supply `locals.env` itself.

For incoming client-disconnect signals on compatibility dates before
2026-11-17, enable `enable_request_signal` in your own Worker configuration.
An observed disconnect does not cancel an already-dispatched D1 operation.
See [Cloudflare's compatibility guidance](https://developers.cloudflare.com/changelog/post/2026-11-02-request-signal-default/).

To install dependencies:

```bash
deno install
```

Dev server (Vite dev):

```bash
deno task dev
```

Cloudflare local dev (optional):

```bash
deno run -A npm:wrangler dev --local
```

Build locally or deploy the configured production environment:

```bash
deno task build
deno task deploy
```

Production deployment requires explicit account and resource configuration;
see [Deployment](docs/DEPLOYMENT.md).

Health endpoints: `GET /health` and `GET /ready` return `200 ok`.

Auth (JWT)
- `POST /xrpc/com.atproto.server.createSession` returns `accessJwt` and `refreshJwt` (HS256).
- `POST /xrpc/com.atproto.server.refreshSession` expects `Authorization: Bearer <refreshJwt>` and issues a new pair.
- Use `Authorization: Bearer <accessJwt>` on write routes.
- Configure the account identity, `USER_PASSWORD` and `REPO_SIGNING_KEY`.
  Modern sessions use `SESSION_JWT_SECRET`, or a key generated in D1 if unset.

Rate limiting & limits
- Per‑IP rate limit (best‑effort, D1‑backed): set `PDS_RATE_LIMIT_PER_MIN` (default writes=1000/min counted per record written, blobs=30/min). Responses include `x-ratelimit-*` headers.
- JSON body size cap via `PDS_MAX_JSON_BYTES` (default 1048576/1 MiB, enough for a full 200-write `applyWrites` batch).
- CORS: allow `*` by default in dev. In production, set `PDS_CORS_ORIGIN` to a CSV of allowed origins (e.g., `https://example.com,https://app.example.com`). Requests with an `Origin` not in this set are denied at the CORS layer (no wildcard fallback).

This project targets Cloudflare Workers via Astro with `@cloudflare/vite-plugin`, and is developed with Deno as the task runner / package manager.

## Database Migrations

This project uses Drizzle Kit for database schema management and migrations.

### Migration Workflow

1. **Modify Schema**: Edit [`src/db/schema.ts`](src/db/schema.ts) to add/modify tables or indexes
2. **Generate Migration**: Run `deno task db:generate` to create a new migration file in `migrations/`
3. **Review Migration**: Check the generated SQL in `migrations/XXXX_*.sql`
4. **Apply Locally**: Run `deno run -A npm:wrangler d1 migrations apply ALTERAN_DB --env dev --local`
5. **Apply to Production**: After verifying the account, database and backup, use `deno run -A npm:wrangler d1 migrations apply ALTERAN_DB --env production --remote`

### Migration Versioning

- Migrations are versioned sequentially (0000, 0001, 0002, etc.)
- Each migration is tracked in `migrations/meta/_journal.json`
- Migrations are applied in order and cannot be skipped
- Applied migrations are recorded in D1's `_cf_KV` table

### Rollback Procedures

**Important**: D1 does not support automatic rollbacks. To rollback:

1. Create a new migration that reverses the changes
2. Test thoroughly in local/staging environment
3. Apply the rollback migration to production

Example rollback migration:
```sql
-- Rollback: Remove index added in 0002
DROP INDEX IF EXISTS `record_cid_idx`;
```

### Data Retention & Pruning

**Commit Log**: Stores full commit history for firehose and sync
- Default retention: Last 10,000 commits
- Pruning: Use [`pruneOldCommits()`](src/lib/commit-log-pruning.ts) utility
- Older commits can be safely removed as current state is in MST

**Blockstore**: Stores MST nodes (Merkle Search Tree blocks)
- Retention: Blocks referenced by recent commits
- GC: Use [`pruneOrphanedBlocks()`](src/lib/blockstore-gc.ts) utility
- Orphaned blocks (not in recent commits) can be removed

**Token Revocation**: Stores revoked JWT tokens
- Automatic cleanup: Expired tokens removed lazily (1% of requests)
- Manual cleanup: Use token cleanup utility
## Configuration Management

See [Configuration](docs/CONFIGURATION.md) and [Deployment](docs/DEPLOYMENT.md).

## P0 Implementation - Core Protocol Compliance ✅

This PDS now implements full AT Protocol core compliance with:

### MST (Merkle Search Tree)
- ✅ Sorted, deterministic tree structure
- ✅ Automatic rebalancing (~4 fanout)
- ✅ Prefix compression for efficiency
- ✅ D1 blockstore integration

### Signed Commits
- ✅ secp256k1 cryptographic signatures
- ✅ AT Protocol v3 commit structure
- ✅ TID-based revisions
- ✅ Commit chain tracking

### Firehose
- ✅ WebSocket-based event stream
- ✅ CBOR-encoded frames (#info, #commit, #identity, #account)
- ✅ Cursor-based replay
- ✅ Backpressure handling
- ✅ Durable Object coordination

### XRPC Endpoints
- ✅ Server: getSession, deleteSession
- ✅ Repo: listRecords, describeRepo, applyWrites
- ✅ Sync: listBlobs, getRecord, listRepos, getLatestCommit
- ✅ Identity: resolveHandle, updateHandle

## Setup Instructions

### 1. Generate Secrets

For a new deployment, generate credentials with the bootstrap script. Do not
replace an existing repository signing key without a reviewed rotation plan.

```bash
# Prints sensitive credentials and environment-specific Wrangler commands
deno run -A scripts/setup-secrets.ts --env production --did did:web:example.com --handle user.example.com --hostname user.example.com

# Alternatively, supply your own secp256k1 key (32‑byte hex/base64)
```

### 2. Configure Secrets

Set `PDS_DID`, `PDS_HANDLE` and `PDS_HOSTNAME` in the named production
`vars` in `wrangler.jsonc`. Replace the checked-in identity with your intended
values and verify that same-name remote secrets do not conflict. After
verifying the account and Worker, configure the credentials:

```bash
deno run -A npm:wrangler secret put REPO_SIGNING_KEY --env production
deno run -A npm:wrangler secret put USER_PASSWORD --env production
# Optional: otherwise the session key is generated and stored in D1
deno run -A npm:wrangler secret put SESSION_JWT_SECRET --env production
```

Clients holding older-format JWTs must authenticate again after upgrading.

**For Local Development (.dev.vars):**
```env
PDS_DID=did:plc:your-did-here
PDS_HANDLE=your-handle.bsky.social
PDS_HOSTNAME=your-handle.bsky.social
REPO_SIGNING_KEY=<hex-secp256k1-private-key>
USER_PASSWORD=your-password
SESSION_JWT_SECRET=your-session-secret
PDS_SEQ_WINDOW=512
```

OAuth client metadata and JWKS documents are fetched dynamically from public
HTTPS URLs using hardened fetch checks: no redirects, public DNS only, size
limits, and timeouts.

### 3. Run Database Migration
```bash
deno run -A npm:wrangler d1 migrations apply ALTERAN_DB --env dev --local
```

Upgrade note: migration `0009_oauth_session_state` revokes existing refresh
tokens when adding OAuth session state. Existing clients may need to sign in
again after this migration. This is intentional because older refresh-token
rows cannot prove whether they came from legacy sessions or pre-hardening OAuth
flows.

### 4. Run Tests
```bash
deno test -A tests/mst.test.ts
deno test -A tests/commit.test.ts
```

### 5. Start Development
```bash
deno task dev
```

## Testing the Implementation

### Test Firehose
```bash
npm install -g wscat
wscat -c "ws://localhost:4321/xrpc/com.atproto.sync.subscribeRepos"
```

### Publish to a Relay (Bluesky)

Relays discover PDSes via `com.atproto.sync.requestCrawl`. Your deployment will automatically notify relays on the first request it handles (and at most every 12 hours per isolate).

- Set your public hostname (bare domain, no protocol):
```
PDS_HOSTNAME=your-pds.example.com
```

- Optional: choose relays to notify (CSV of hostnames). Defaults to `bsky.network`.
```
PDS_RELAY_HOSTS=bsky.network
```

- To trigger manually from your machine:
```bash
curl -X POST "https://bsky.network/xrpc/com.atproto.sync.requestCrawl" \
     -H "Content-Type: application/json" \
     -d '{"hostname":"your-pds.example.com"}'
```

Notes:
- Use only the hostname in `hostname` (no `https://`).
- Ensure your PDS is publicly reachable over HTTPS/WSS and that DID documents resolve to this hostname.

### Test XRPC Endpoints
```bash
# Get session
curl http://localhost:4321/xrpc/com.atproto.server.getSession

# Describe repo
curl "http://localhost:4321/xrpc/com.atproto.repo.describeRepo?repo=did:example:single-user"

# List records
curl "http://localhost:4321/xrpc/com.atproto.repo.listRecords?repo=did:example:single-user&collection=app.bsky.feed.post"
```

## Documentation

- [Configuration](docs/CONFIGURATION.md) and [Deployment](docs/DEPLOYMENT.md)
- [Additional repository documentation](https://github.com/alteran-social/alteran/tree/main/docs)

Repo signing key (REQUIRED)
  
- Store as `REPO_SIGNING_KEY` secret (base64-encoded private key)

## P1 Implementation - Production Readiness 🚀

This PDS now includes production-grade features for security, observability, and reliability:

### Authentication Hardening
- ✅ **Single-use refresh tokens** with JTI tracking
- ✅ **Token rotation** on every refresh
- ✅ **Automatic token cleanup** (lazy cleanup on 1% of requests)
- ✅ **Account lockout** after 5 failed login attempts (15-minute lockout)
  
- ✅ **Proper JWT claims**: `sub`, `aud`, `iat`, `exp`, `jti`, `scope`
- ✅ **Production CORS validation** (no wildcard in production)

### Error Handling
- ✅ **XRPC error hierarchy** with AT Protocol error codes
- ✅ **Consistent error responses** with user-friendly messages
- ✅ **Error categorization** (client vs server errors)
- ✅ **Request ID tracking** in all error responses

### Observability
- ✅ **Structured JSON logging** with levels (debug, info, warn, error)
- ✅ **Request ID tracking** in all logs and response headers
- ✅ **Enhanced health checks** for D1 and R2 dependencies
- ✅ **Performance metrics** in request logs (duration, status)

### Additional Configuration

**JWT Configuration:**
```bash
# Service-auth uses ES256K (secp256k1) exclusively
PDS_HOSTNAME=your-pds.example.com
PDS_ACCESS_TTL_SEC=3600          # 1 hour
PDS_REFRESH_TTL_SEC=2592000      # 30 days
# No JWT_ALGORITHM flag; ES256K is always used for AppView service tokens
```

**CORS Configuration:**
```bash
# Comma-separated list of allowed origins (no wildcard in production)
PDS_CORS_ORIGIN=https://app.example.com,https://admin.example.com
```

### Logging & Monitoring

**View logs in development:**
```bash
wrangler tail --format=pretty
```

**View logs in production:**
```bash
wrangler tail --env production --format=json
```

**Configure Logpush (production):**
1. Set up Logpush in Cloudflare dashboard
2. Send logs to your preferred service (Datadog, Splunk, S3, etc.)
3. Filter by `requestId` for request tracing

**Log format:**
```json
{
  "level": "info",
  "type": "request",
  "requestId": "uuid",
  "method": "POST",
  "path": "/xrpc/com.atproto.repo.createRecord",
  "status": 200,
  "duration": 45,
  "timestamp": "2025-10-02T22:00:00.000Z"
}
```

### Health Check

**Endpoint:** `GET /health`

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2025-10-02T22:00:00.000Z",
  "checks": {
    "database": { "status": "ok" },
    "storage": { "status": "ok" }
  }
}
```

Returns `503` if any dependency is unhealthy.

### Security Best Practices

1. **Never use wildcard CORS in production** - Set explicit origins in `PDS_CORS_ORIGIN`
2. **Use strong secrets** - Generate cryptographically secure values for all secrets
3. **Use ES256K (secp256k1) signing**
4. **Monitor failed login attempts** - Check logs for suspicious activity
5. **Set appropriate token TTLs** - Balance security and user experience

## P3 Implementation - Optimization & Interoperability 🚀

This PDS now includes optimization for Cloudflare Workers and interoperability features:

### Cloudflare Workers Optimization
- ✅ **Streaming CAR encoding** for memory efficiency (< 128MB)
- ✅ **Edge caching** for DID documents and static assets
- ✅ **Performance tests** verifying CPU and memory constraints
- ✅ **Memory-efficient operations** for large repositories

### Blob Storage Enhancement
- ✅ **Blob quota tracking** per DID (default: 10GB)
- ✅ **Quota enforcement** on upload
- ✅ **Reference counting** for garbage collection
- ✅ **Deduplication** by content-addressed storage

### Identity Enhancement
- ✅ **DID document generation** at `/.well-known/did.json`
- ✅ **Handle validation** and normalization
- ✅ **Service endpoints** in DID document
- ✅ **Edge caching** for identity documents

### Interoperability Testing
- ✅ **Federation test stubs** for PDS-to-PDS sync
- ✅ **Compliance test stubs** for AT Protocol
- ✅ **Protocol version** documentation
- ✅ **Lexicon validation** framework

### Configuration

**Blob Quota:**
```bash
PDS_BLOB_QUOTA_BYTES=10737418240  # Default: 10GB
```

**Caching (automatic):**
- DID documents: 1 hour TTL, 24 hour stale-while-revalidate
- Records: 1 minute TTL, 5 minute stale-while-revalidate
- Repo snapshots: 5 minute TTL, 1 hour stale-while-revalidate

### Testing

```bash
# Performance tests
deno test -A tests/performance.test.ts

# Memory tests
deno test -A tests/memory.test.ts

# Blob tests
deno test -A tests/blob.test.ts

# Identity tests
deno test -A tests/identity.test.ts

# Federation tests
deno test -A tests/federation.test.ts

# Compliance tests
deno test -A tests/compliance.test.ts
```

- Used for signing all repository commits
