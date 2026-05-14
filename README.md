# Alteran

> [!WARNING]
> This project was built using agentic coding tools and is currently undergoing a systematic review by a human in their spare time. Nobody should use this project as their PDS yet.

## Astro Integration

This repository now ships an Astro integration that turns any Cloudflare Worker-backed Astro app into a single-user ATProto Personal Data Server. Install the package (or link it locally), then add the integration to your `astro.config.mjs`:

```bash
npm install @alteran/astro
# or
bun add @alteran/astro
```

```ts
import { defineConfig } from 'astro/config';
import cloudflare from '@astrojs/cloudflare';
import alteran from '@alteran/astro';

export default defineConfig({
  adapter: cloudflare({ mode: 'advanced' }),
  integrations: [alteran()],
});
```

By default the integration injects all `/xrpc/*` ATProto routes, health/ready checks, and the Cloudflare Worker entrypoint that wires `locals.runtime`. Optional flags let you expose the `/debug/*` utilities or keep your own homepage:

```ts
alteran({
  debugRoutes: process.env.NODE_ENV !== 'production',
  includeRootEndpoint: false,
  injectServerEntry: true, // opt in if you don't maintain your own worker entrypoint
});
```

The integration automatically:
- Resolves all injected routes against the packaged runtime without requiring a Vite alias
- Registers the middleware that applies structured logging and CORS enforcement
- Injects all PDS HTTP endpoints into the host project
- Offers the packaged Cloudflare worker entrypoint when you enable `{ injectServerEntry: true }`
- Publishes ambient env typings so `Env` and `App.Locals` are available from TypeScript

When deploying, continue to configure Wrangler/D1/R2 secrets exactly as before—the integration does not change the runtime requirements.

### Custom Worker Entrypoint

The integration no longer overrides `build.serverEntry` by default. If you need to export additional Durable Objects or otherwise customise the worker, keep your own entrypoint and compose Alteran's runtime helpers instead of copying the internal logic.

```ts
// src/_worker.ts in your Astro project
import { createPdsFetchHandler, Sequencer } from '@alteran/astro/worker';

const fetch = createPdsFetchHandler();

export default { fetch };

// Re-export Sequencer so Wrangler can bind the Durable Object namespace
export { Sequencer };

// Export any additional Durable Objects after this line
export { MyDurableObject } from './worker/my-durable-object';
```

Helpers like `onRequest`, `seed`, and `validateConfigOrThrow` are also exported from `@alteran/astro/worker` if you need to build more advanced wrappers (for example, to add request instrumentation before delegating to the PDS handler).

To install dependencies:

```bash
bun install
```

Dev server (Vite dev):

```bash
bun run dev
```

Cloudflare local dev (optional):

```bash
bunx wrangler dev --local
```

Build and deploy:

```bash
bun run build
bun run deploy
```

Health endpoints: `GET /health` and `GET /ready` return `200 ok`.

Auth (JWT)
- `POST /xrpc/com.atproto.server.createSession` returns `accessJwt` and `refreshJwt` (HS256).
- `POST /xrpc/com.atproto.server.refreshSession` expects `Authorization: Bearer <refreshJwt>` and issues a new pair.
- Use `Authorization: Bearer <accessJwt>` on write routes.
- Secrets to set (Wrangler secrets or local bindings):
  - `USER_PASSWORD` (dev login password)
  - `ACCESS_TOKEN`, `REFRESH_TOKEN` (HMAC keys)
  - `PDS_DID`, `PDS_HANDLE`

Rate limiting & limits
- Per‑IP rate limit (best‑effort, D1‑backed): set `PDS_RATE_LIMIT_PER_MIN` (default writes=60/min, blobs=30/min). Responses include `x-ratelimit-*` headers.
- JSON body size cap via `PDS_MAX_JSON_BYTES` (default 65536/64 KiB).
- CORS: allow `*` by default in dev. In production, set `PDS_CORS_ORIGIN` to a CSV of allowed origins (e.g., `https://example.com,https://app.example.com`). Requests with an `Origin` not in this set are denied at the CORS layer (no wildcard fallback).

This project was created using `bun init` in bun v1.2.22 and configured for Cloudflare Workers with Vite and `@cloudflare/vite-plugin`.

## Database Migrations

This project uses Drizzle Kit for database schema management and migrations.

### Migration Workflow

1. **Modify Schema**: Edit [`src/db/schema.ts`](src/db/schema.ts:1) to add/modify tables or indexes
2. **Generate Migration**: Run `bun run db:generate` to create a new migration file in `migrations/`
3. **Review Migration**: Check the generated SQL in `migrations/XXXX_*.sql`
4. **Apply Locally**: Run `bun run db:apply:local` to apply to local D1 database
5. **Apply to Production**: Run `wrangler d1 migrations apply pds --remote` after deployment

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
- Pruning: Use [`pruneOldCommits()`](src/lib/commit-log-pruning.ts:19) utility
- Older commits can be safely removed as current state is in MST

**Blockstore**: Stores MST nodes (Merkle Search Tree blocks)
- Retention: Blocks referenced by recent commits
- GC: Use [`pruneOrphanedBlocks()`](src/lib/blockstore-gc.ts:127) utility
- Orphaned blocks (not in recent commits) can be removed

**Token Revocation**: Stores revoked JWT tokens
- Automatic cleanup: Expired tokens removed lazily (1% of requests)
- Manual cleanup: Use token cleanup utility
## Configuration Management

### Environment Setup

This PDS supports multiple environments (dev, staging, production) with separate configurations.

**Deploy to specific environment:**
```bash
# Development
wrangler deploy --env dev

# Staging
wrangler deploy --env staging

# Production
wrangler deploy --env production
```

### Required Secrets

Set these secrets for each environment using `wrangler secret put <NAME> --env <environment>`:

| Secret | Description | Example |
|--------|-------------|---------|
| `PDS_DID` | Your DID identifier | `did:plc:abc123` or `did:web:example.com` |
| `PDS_HANDLE` | Your handle | `user.bsky.social` |
| `USER_PASSWORD` | Login password | Strong password |
| `ACCESS_TOKEN` | JWT access token secret | Random 32+ char string |
| `REFRESH_TOKEN` | JWT refresh token secret | Random 32+ char string |
| `REPO_SIGNING_KEY` | secp256k1 signing key (hex or base64 32 bytes). Used for commits and service-auth | From `scripts/setup-secrets.ts` |

**Generate secrets:**
```bash
# One-shot bootstrap (recommended)
# Generates all required secrets and prints wrangler commands
bun run scripts/setup-secrets.ts --env production --did did:web:example.com --handle user.example.com

# After generation, set secrets (example for production)
wrangler secret put PDS_DID --env production
wrangler secret put PDS_HANDLE --env production
wrangler secret put USER_PASSWORD --env production
wrangler secret put ACCESS_TOKEN --env production
wrangler secret put REFRESH_TOKEN --env production
wrangler secret put REPO_SIGNING_KEY --env production
```

### Using Cloudflare Secret Store (optional)

Instead of Wrangler Secrets, you may bind secrets from Cloudflare Secret Store. This repo now supports both. Bind each secret you want to source from Secret Store via `secrets_store_secrets` in `wrangler.jsonc`:

```jsonc
{
  // ...
  "secrets_store_secrets": [
    { "binding": "USER_PASSWORD", "secret_name": "user_password", "store_id": "<your-store-id>" },
    { "binding": "ACCESS_TOKEN", "secret_name": "access_token", "store_id": "<your-store-id>" },
    { "binding": "REFRESH_TOKEN", "secret_name": "refresh_token", "store_id": "<your-store-id>" },
    { "binding": "PDS_DID", "secret_name": "pds_did", "store_id": "<your-store-id>" },
    { "binding": "PDS_HANDLE", "secret_name": "pds_handle", "store_id": "<your-store-id>" }
  ]
}
```

Notes:
- Bindings can use the same names as the existing env vars. Only one source should be configured per secret (Wrangler Secret OR Secret Store binding).
- At runtime, the worker resolves Secret Store bindings via `await env.<BINDING>.get()` and passes them to the app as plain strings.

### Optional Configuration

These can be set as environment variables in [`wrangler.jsonc`](wrangler.jsonc:1) or as secrets:

| Variable | Default | Description |
|----------|---------|-------------|
| `PDS_ALLOWED_MIME` | `image/jpeg,image/png,...` | Comma-separated MIME types |
| `PDS_MAX_BLOB_SIZE` | `5242880` (5MB) | Max blob size in bytes |
| `PDS_MAX_JSON_BYTES` | `65536` (64KB) | Max JSON body size |
| `PDS_RATE_LIMIT_PER_MIN` | `60` | Write requests per minute |
| `PDS_CORS_ORIGIN` | `*` (dev), specific (prod) | Allowed CORS origins |
| `PDS_SEQ_WINDOW` | `512` | Firehose sequence window |
| `PDS_HOSTNAME` | - | Public hostname |
| `PDS_ACCESS_TTL_SEC` | `3600` (1 hour) | Access token TTL |
| `PDS_REFRESH_TTL_SEC` | `2592000` (30 days) | Refresh token TTL |

### Configuration Validation

The PDS validates configuration on startup and will fail fast if required secrets are missing:

```typescript
// Automatic validation in src/_worker.ts
validateConfigOrThrow(env);
```

**Validation checks:**
- All required secrets are present
- CORS is not wildcard in production
- DID format is valid
- Handle format is valid
- Numeric values are positive

### Cloudflare Security Rules

`com.atproto.server.refreshSession` is a valid bodyless `POST`. Production deployments must allow this request shape through to the XRPC handler:

```txt
(http.request.method eq "POST" and http.request.uri.path eq "/xrpc/com.atproto.server.refreshSession")
```

Astro's SSR origin-check middleware rejects unsafe requests with no `Origin` header before project middleware runs. Alteran normalizes `/xrpc/*` requests at the Worker entrypoint so bearer-token XRPC clients can send bodyless POSTs without tripping Astro's form CSRF guard.

If Cloudflare WAF/API Shield also protects the deployment, keep any exception narrow to the expression above. This exception is not configured in `wrangler.jsonc`; Wrangler only manages the Worker deployment and bindings.

### Environment-Specific Settings

See [`wrangler.jsonc`](wrangler.jsonc:40) for environment-specific configurations:

- **Development**: Relaxed CORS, larger blob limits, local D1/R2
- **Staging**: Production-like settings, separate D1/R2 instances
- **Production**: Strict CORS, production D1/R2, observability enabled


Debugging & storage
- D1 schema/migrations: generated with Drizzle Kit into `drizzle/`. Generate with `bunx drizzle-kit generate`.
- Apply schema locally: `bunx wrangler d1 migrations apply pds --local` (requires dev DB named `pds`).
- Bootstrap route (alt): `POST /debug/db/bootstrap` creates a minimal `record` table.
- Insert a test record: `POST /debug/record` with `{ "uri": "at://did:example/app.bsky.feed.post/123", "json": {"msg":"hi"} }`.
- Get a record: `GET /debug/record?uri=at://did:example/app.bsky.feed.post/123`.
- R2 test: `PUT /debug/blob/<key>` and `GET /debug/blob/<key>`.
- Run GC: `POST /debug/gc/blobs` removes R2 objects with no references

XRPC surface
- `GET /xrpc/com.atproto.server.describeServer`
- `POST /xrpc/com.atproto.server.createSession` (returns JWTs)
- `POST /xrpc/com.atproto.server.refreshSession`
- `GET /xrpc/com.atproto.repo.getRecord?uri=...` (reads from D1 `record` table) or `repo+collection+rkey`
- `POST /xrpc/com.atproto.repo.createRecord` (auth required)
- `POST /xrpc/com.atproto.repo.putRecord` (auth required)
- `POST /xrpc/com.atproto.repo.deleteRecord` (auth required)
- `POST /xrpc/com.atproto.repo.uploadBlob` (auth + MIME allowlist)
  - Stores blob metadata in `blob` table (`cid`=sha256 b64url, `mime`, `size`)
  - Blob references inside records tracked by R2 key; deleting a record drops usage and GC can reclaim orphaned objects

Sync (minimal JSON variants)
- `GET /xrpc/com.atproto.sync.getHead` → `{ root, rev }`
- `GET /xrpc/com.atproto.sync.getRepo.json?did=<did>` → `{ did, head, rev, records: [{uri,cid,value}] }`
- `GET /xrpc/com.atproto.sync.getCheckout.json?did=<did>` → same as above
- `GET /xrpc/com.atproto.sync.getBlocks.json?cids=<cid1,cid2>` → `{ blocks: [{cid,value}] }`

Sync (CAR v1)
- `GET /xrpc/com.atproto.sync.getRepo?did=<did>` → `application/vnd.ipld.car` snapshot
- `GET /xrpc/com.atproto.sync.getCheckout?did=<did>` → same as above
- `GET /xrpc/com.atproto.sync.getBlocks?cids=<cid1,cid2>` → `application/vnd.ipld.car` with requested blocks
  - Blocks are DAG-CBOR encoded; CIDs are CIDv1 (dag-cbor + sha2-256)

Firehose (WebSocket)
- `GET /xrpc/com.atproto.sync.subscribeRepos` upgrades to WebSocket.
- On writes, the worker POSTs a small commit frame to the `Sequencer` Durable Object, which broadcasts to all subscribers.
- Frames (subject to change):
  - `{"type":"hello","now":<ms>}` once on connect
  - `{"type":"commit","did":"...","commitCid":"...","rev":<n>,"ts":<ms>}` on each write

Blob storage
- Keys are content-addressed: `blobs/by-cid/<sha256-b64url>`; upload response `$link` equals this key.
- Allowed MIME types via `PDS_ALLOWED_MIME` (CSV). Size limit via `PDS_MAX_BLOB_SIZE` (bytes).

Secrets & config (Wrangler)
- Required:
  - `PDS_DID`, `PDS_HANDLE`, `USER_PASSWORD`
  - `ACCESS_TOKEN`, `REFRESH_TOKEN`
- Optional:
  - `PDS_ALLOWED_MIME`, `PDS_MAX_BLOB_SIZE`, `PDS_MAX_JSON_BYTES`, `PDS_RATE_LIMIT_PER_MIN`, `PDS_CORS_ORIGIN`
- Durable Objects: ensure binding for `Sequencer` exists and migration tag added (see `wrangler.jsonc`).

Identity (DID)
- This single‑user PDS uses `did:web`.
- Host `/.well-known/atproto-did` on your production domain with the DID value.
- Set `PDS_DID` and `PDS_HANDLE` secrets to match your deployment.

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
```bash
# Recommended: bootstrap all secrets (prints wrangler commands)
bun run scripts/setup-secrets.ts --env production --did did:web:example.com --handle user.example.com

# Alternatively, supply your own secp256k1 key (32‑byte hex/base64)
```

### 2. Configure Secrets

**Required Secrets:**
```bash
wrangler secret put REPO_SIGNING_KEY         # secp256k1 (from setup-secrets)
wrangler secret put PDS_DID                  # Your DID
wrangler secret put PDS_HANDLE               # Your handle
wrangler secret put USER_PASSWORD            # Login password
wrangler secret put REFRESH_TOKEN
wrangler secret put REFRESH_TOKEN_SECRET
```

**For Local Development (.dev.vars):**
```env
PDS_DID=did:plc:your-did-here
PDS_HANDLE=your-handle.bsky.social
REPO_SIGNING_KEY=<hex-secp256k1-private-key>
USER_PASSWORD=your-password
REFRESH_TOKEN=your-access-secret
REFRESH_TOKEN_SECRET=your-refresh-secret
PDS_SEQ_WINDOW=512
```

OAuth client metadata and JWKS documents are fetched dynamically from public
HTTPS URLs using hardened fetch checks: no redirects, public DNS only, size
limits, and timeouts.

### 3. Run Database Migration
```bash
bun run db:generate
bun run db:apply:local
```

Upgrade note: migration `0009_oauth_session_state` revokes existing refresh
tokens when adding OAuth session state. Existing clients may need to sign in
again after this migration. This is intentional because older refresh-token
rows cannot prove whether they came from legacy sessions or pre-hardening OAuth
flows.

### 4. Run Tests
```bash
bun test tests/mst.test.ts
bun test tests/commit.test.ts
```

### 5. Start Development
```bash
bun run dev
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

- [`P0_COMPLETE.md`](P0_COMPLETE.md) - Full P0 implementation details
- [`P0_IMPLEMENTATION_SUMMARY.md`](P0_IMPLEMENTATION_SUMMARY.md) - Technical summary
- [`PROGRESS.md`](PROGRESS.md) - Development progress notes

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

### Documentation

- [`P1_IMPLEMENTATION_SUMMARY.md`](P1_IMPLEMENTATION_SUMMARY.md) - Full P1 implementation details
- [`P1.md`](P1.md) - P1 task breakdown and requirements

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
- ✅ **Federation tests** for local sync, CAR, blob, and subscribeRepos surfaces
- ✅ **Compliance tests** for AT Protocol lexicons, auth flows, and XRPC errors
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
bun test tests/performance.test.ts

# Memory tests
bun test tests/memory.test.ts

# Blob tests
bun test tests/blob.test.ts

# Identity tests
bun test tests/identity.test.ts

# Federation tests
bun test tests/federation.test.ts

# Compliance tests
bun test tests/compliance.test.ts
```

### Documentation

- [`P3_IMPLEMENTATION_SUMMARY.md`](P3_IMPLEMENTATION_SUMMARY.md) - Full P3 implementation details
- [`P3.md`](P3.md) - P3 task breakdown and requirements

- Used for signing all repository commits
