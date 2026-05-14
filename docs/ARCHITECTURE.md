# Architecture Documentation

This document describes the architecture of the Cloudflare-native PDS implementation.

## Overview

This PDS is built specifically for Cloudflare Workers, leveraging Cloudflare's edge platform for global distribution and performance.

```
┌─────────────────────────────────────────────────────────────┐
│                        Client Apps                           │
│              (Bluesky, custom clients, etc.)                 │
└────────────────────┬────────────────────────────────────────┘
                     │ HTTPS/WebSocket
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                   Cloudflare Worker                          │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              Request Handler                          │   │
│  │  • Authentication (JWT)                               │   │
│  │  • Rate Limiting                                      │   │
│  │  • CORS                                               │   │
│  │  • Request Validation                                 │   │
│  └──────────────────────────────────────────────────────┘   │
│                     │                                         │
│  ┌──────────────────┼────────────────────────────────────┐   │
│  │                  ▼                                     │   │
│  │         XRPC Route Handlers                           │   │
│  │  • Server (auth, session)                             │   │
│  │  • Repo (CRUD operations)                             │   │
│  │  • Sync (CAR export, firehose)                        │   │
│  │  • Identity (handle resolution)                       │   │
│  └───────────────────────────────────────────────────────┘   │
│                     │                                         │
│  ┌──────────────────┼────────────────────────────────────┐   │
│  │                  ▼                                     │   │
│  │            Core Services                              │   │
│  │  • RepoManager (MST operations)                       │   │
│  │  • CAR Builder (export)                               │   │
│  │  • Commit Signing (secp256k1)                         │   │
│  │  • Blob Management                                    │   │
│  └───────────────────────────────────────────────────────┘   │
└────────────┬──────────────────┬──────────────┬──────────────┘
             │                  │              │
             ▼                  ▼              ▼
┌────────────────────┐ ┌──────────────┐ ┌─────────────────┐
│    D1 Database     │ │  R2 Storage  │ │ Durable Object  │
│                    │ │              │ │   (Sequencer)   │
│ • Records          │ │ • Blobs      │ │                 │
│ • MST Blocks       │ │ • Images     │ │ • Firehose      │
│ • Commits          │ │ • Videos     │ │ • WebSocket     │
│ • Tokens           │ │              │ │ • Broadcasting  │
└────────────────────┘ └──────────────┘ └─────────────────┘
```

## Components

### 1. Worker Entry Point

**File**: [`src/_worker.ts`](../src/_worker.ts:1)

The main entry point for all requests. Handles:
- Configuration validation
- Database seeding
- WebSocket upgrade for firehose
- Request routing to Astro handler

### 2. Middleware Layer

**File**: [`src/middleware.ts`](../src/middleware.ts:1)

Processes all requests before routing:
- Authentication (JWT validation)
- Rate limiting (per-IP)
- CORS headers
- Request logging
- Error handling

### 3. XRPC Handlers

**Directory**: `src/pages/xrpc/`

Each XRPC method has its own handler file:
- **Server**: Session management, authentication
- **Repo**: Record CRUD, blob uploads
- **Sync**: Repository export, firehose subscription
- **Identity**: Handle resolution, DID management

### 4. Core Services

#### RepoManager

**File**: [`src/services/repo-manager.ts`](../src/services/repo-manager.ts:1)

Manages repository operations:
- MST (Merkle Search Tree) operations
- Record insertion/deletion
- Commit creation and signing
- Repository state management

#### MST (Merkle Search Tree)

**Directory**: `src/lib/mst/`

Implements the AT Protocol MST:
- **mst.ts**: Core MST logic (insert, delete, traverse)
- **blockstore.ts**: D1-backed block storage
- **util.ts**: MST utilities (CID calculation, encoding)

Key features:
- Sorted, deterministic tree structure
- Automatic rebalancing (~4 fanout)
- Prefix compression
- CBOR encoding

#### Commit System

**File**: [`src/lib/commit.ts`](../src/lib/commit.ts:1)

Handles repository commits:
- secp256k1 signature generation
- AT Protocol v3 commit structure
- TID-based revisions
- Commit chain tracking

#### CAR Builder

**File**: [`src/services/car.ts`](../src/services/car.ts:1)

Builds CAR (Content Addressable aRchive) files:
- Repository snapshots
- Block export
- Streaming CAR generation

#### Blob Storage

**File**: [`src/services/r2-blob-store.ts`](../src/services/r2-blob-store.ts:1)

Manages blob storage in R2:
- Content-addressed storage
- MIME type validation
- Size limits
- Garbage collection

### 5. Firehose (Durable Object)

**File**: [`src/worker/sequencer.ts`](../src/worker/sequencer.ts:1)

Implements the firehose event stream:
- WebSocket connection management
- CBOR frame encoding
- Cursor-based replay
- Backpressure handling
- Broadcast to all subscribers

Frame types:
- `#info`: Connection info, errors
- `#commit`: Repository updates
- `#identity`: Handle changes
- `#account`: Account events

### 6. Database Layer

#### Schema

**File**: [`src/db/schema.ts`](../src/db/schema.ts:1)

Drizzle ORM schema definitions:
- `repo_root`: Repository metadata
- `record`: User records
- `blob_ref`: Blob metadata
- `blob_usage`: Blob-record relationships
- `commit_log`: Commit history
- `blockstore`: MST nodes
- `token_revocation`: Revoked JWTs
- `login_attempts`: Rate limiting

#### DAL (Data Access Layer)

**File**: [`src/db/dal.ts`](../src/db/dal.ts:1)

Database operations:
- Record CRUD
- Blob management
- Garbage collection queries

### 7. Authentication

**File**: [`src/lib/auth.ts`](../src/lib/auth.ts:1)

JWT-based authentication:
- HS256 signing
- Access tokens (1 hour TTL)
- Refresh tokens (30 day TTL)
- Single-use refresh tokens
- Token revocation
- Account lockout (5 failed attempts)

### 8. Observability

#### Logging

**File**: [`src/lib/logger.ts`](../src/lib/logger.ts:1)

Structured JSON logging:
- Request tracking (request ID)
- Performance metrics
- Error tracking
- Log levels (debug, info, warn, error)

#### Metrics

**File**: [`src/lib/metrics.ts`](../src/lib/metrics.ts:1)

Performance metrics:
- Request duration
- Database query time
- Error rates

#### Health Checks

**Files**: `src/pages/health.ts`, `src/pages/ready.ts`

Service health monitoring:
- Database connectivity
- R2 storage availability
- Overall service status

## Data Flow

### Write Operation (Create Record)

```
1. Client → POST /xrpc/com.atproto.repo.createRecord
   ↓
2. Middleware validates JWT, checks rate limit
   ↓
3. XRPC handler validates request body
   ↓
4. RepoManager:
   a. Load current MST from blockstore
   b. Insert new record into MST
   c. Serialize MST to blocks
   d. Store blocks in D1 blockstore
   e. Create commit object
   f. Sign commit with secp256k1
   g. Store commit in commit_log
   h. Update repo_root
   ↓
5. Notify Sequencer DO of new commit
   ↓
6. Sequencer broadcasts to firehose subscribers
   ↓
7. Return URI and CID to client
```

### Read Operation (Get Record)

```
1. Client → GET /xrpc/com.atproto.repo.getRecord
   ↓
2. Middleware (no auth required for reads)
   ↓
3. XRPC handler validates query params
   ↓
4. Query D1 record table directly
   ↓
5. Return record value to client
```

### Sync Operation (Export Repository)

```
1. Client → GET /xrpc/com.atproto.sync.getRepo
   ↓
2. CAR Builder:
   a. Load latest commit from commit_log
   b. Traverse MST from root
   c. Collect all blocks (MST nodes + records)
   d. Encode as CAR v1
   ↓
3. Stream CAR file to client
```

### Firehose Subscription

```
1. Client → WebSocket upgrade to /xrpc/com.atproto.sync.subscribeRepos
   ↓
2. Worker forwards to Sequencer DO
   ↓
3. Sequencer:
   a. Accept WebSocket connection
   b. Send #info frame
   c. If cursor provided, replay from that point
   d. Subscribe to new commits
   ↓
4. On each write:
   a. Worker notifies Sequencer
   b. Sequencer encodes #commit frame (CBOR)
   c. Broadcast to all subscribers
```

## Storage Architecture

### D1 Database

**Purpose**: Structured data storage

**Tables**:
- Records (with indexes on did, cid)
- MST blocks (blockstore)
- Commit log (with pruning)
- Authentication (tokens, login attempts)

**Characteristics**:
- SQLite-based
- Eventually consistent
- Query limits: 50ms CPU time
- Storage limits: 10GB per database

### R2 Storage

**Purpose**: Blob storage (images, videos)

**Structure**:
```
blobs/
  by-cid/
    <sha256-base64url>  # Content-addressed
```

**Characteristics**:
- Object storage
- Globally distributed
- No egress fees
- Storage limits: Unlimited

### Durable Objects

**Purpose**: Stateful coordination

**Use Cases**:
- Firehose sequencing
- WebSocket connection management
- Event broadcasting

**Characteristics**:
- Single-threaded
- Strongly consistent
- Persistent storage
- Global uniqueness

## Scaling Considerations

### Horizontal Scaling

Workers automatically scale:
- No configuration needed
- Handles millions of requests
- Global distribution

### Database Scaling

D1 limitations:
- Single database per binding
- 50ms CPU time per query
- Consider read replicas for high traffic

Mitigation strategies:
- Efficient indexes
- Query optimization
- Caching (future)

### Storage Scaling

R2 scales automatically:
- No limits on object count
- No limits on storage size
- Global replication

### Firehose Scaling

Durable Object limitations:
- Single instance per name
- Limited concurrent connections (~10k)

Mitigation strategies:
- Multiple sequencer instances (sharding)
- Connection pooling
- Backpressure handling

## Security Architecture

### Authentication Flow

```
1. Login → createSession
   ↓
2. Generate access JWT (1h) + refresh JWT (30d)
   ↓
3. Client stores tokens
   ↓
4. Requests use access JWT
   ↓
5. Access expires → refreshSession with refresh JWT
   ↓
6. New token pair issued, old refresh revoked
```

### Authorization

- Single-user PDS: All authenticated requests authorized
- Multi-user: Would need per-user authorization checks
- Public signup, invite queues, hosted account recovery, local
  moderation/report triage, and ToS-acceptance workflows are deliberate
  single-user non-goals. See
  [`SINGLE_USER_BOUNDARIES.md`](SINGLE_USER_BOUNDARIES.md).

### Rate Limiting

Per-IP rate limiting:
- Stored in D1 (login_attempts table)
- 60 writes/minute default
- 30 blob uploads/minute default
- Account lockout after 5 failed logins

### CORS

Environment-specific:
- Development: `*` (all origins)
- Production: Explicit origin list

## Performance Optimizations

### Database

- Indexes on frequently queried columns
- Efficient MST traversal
- Batch operations where possible

### Caching

Current: None (stateless workers)
Future: Consider Cloudflare KV for:
- DID documents
- Handle resolutions
- Public records

### CDN

Cloudflare automatically caches:
- Static assets
- Immutable responses (with proper headers)

## Monitoring & Observability

### Logs

Structured JSON logs with:
- Request ID tracking
- Performance metrics
- Error details

Access via:
```bash
wrangler tail --format=json
```

### Metrics

Cloudflare Workers Analytics:
- Request count
- Error rate
- Latency (p50, p95, p99)
- CPU time

### Alerts

Configure in Cloudflare dashboard:
- High error rate
- High latency
- Resource exhaustion

## Deployment Architecture

### Environments

- **Development**: Local Miniflare + local D1/R2
- **Staging**: Cloudflare Workers + staging D1/R2
- **Production**: Cloudflare Workers + production D1/R2

### CI/CD

Recommended flow:
```
1. Push to main
   ↓
2. Run tests (Deno test)
   ↓
3. Build (Astro build)
   ↓
4. Deploy to staging (wrangler deploy --env staging)
   ↓
5. Run smoke tests
   ↓
6. Deploy to production (wrangler deploy --env production)
   ↓
7. Monitor
```

### Rollback

1. Revert to previous deployment:
   ```bash
   wrangler rollback --env production
   ```

2. Or deploy specific version:
   ```bash
   wrangler deploy --env production --version <version>
   ```

## Future Enhancements

### Planned

- [ ] Multi-user support
- [ ] Caching layer (KV)
- [ ] Advanced rate limiting
- [ ] Metrics dashboard
- [ ] Automated backups

### Considered

- [ ] Read replicas (D1)
- [ ] CDN optimization
- [ ] Advanced monitoring
- [ ] A/B testing framework

## References

- [AT Protocol Specification](https://atproto.com/specs/atp)
- [Cloudflare Workers Docs](https://developers.cloudflare.com/workers/)
- [D1 Documentation](https://developers.cloudflare.com/d1/)
- [R2 Documentation](https://developers.cloudflare.com/r2/)
- [Durable Objects](https://developers.cloudflare.com/durable-objects/)
