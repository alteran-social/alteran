# API Documentation

Complete reference for all XRPC endpoints provided by this PDS.

## Base URL

```
https://your-pds.example.com
```

## Authentication

Most endpoints require authentication via JWT Bearer token:

```
Authorization: Bearer <accessJwt>
```

Obtain tokens via [`com.atproto.server.createSession`](#comatprotoservercreatesession).

## Error Responses

All errors follow the XRPC error format:

```json
{
  "error": "ErrorCode",
  "message": "Human-readable error message"
}
```

Common error codes:
- `AuthenticationRequired` (401): Missing or invalid auth token
- `InvalidRequest` (400): Malformed request
- `NotFound` (404): Resource not found
- `NotImplemented` (501): Known endpoint intentionally unsupported by Alteran
- `RateLimitExceeded` (429): Too many requests
- `InternalServerError` (500): Server error

---

## Intentionally Unsupported Single-User Routes

Alteran is a single-user PDS. Public signup, invite-code management, signup
queues, and broad admin account-management APIs are intentionally unsupported.
Known unsupported XRPC routes return a stable JSON error before auth is required:

```json
{
  "error": "NotImplemented",
  "message": "<nsid> is intentionally unsupported by Alteran single-user PDS"
}
```

The unsupported set includes:

- `com.atproto.server.createAccount`
- `com.atproto.server.reserveSigningKey`
- `com.atproto.server.createInviteCode`
- `com.atproto.server.createInviteCodes`
- `com.atproto.server.getAccountInviteCodes`
- `com.atproto.admin.*`
- `com.atproto.temp.addReservedHandle`
- `com.atproto.temp.checkHandleAvailability`
- `com.atproto.temp.checkSignupQueue`
- `com.atproto.temp.requestPhoneVerification`
- `com.atproto.temp.revokeAccountCredentials`

---

## Server Endpoints

### com.atproto.server.describeServer

Get server information and capabilities.

**Method**: `GET`
**Auth**: Not required

**Response**:
```json
{
  "did": "did:web:example.com",
  "availableUserDomains": [],
  "inviteCodeRequired": false,
  "phoneVerificationRequired": false
}
```

`availableUserDomains: []` is intentional: this package does not expose public
account creation. `inviteCodeRequired: false` means Alteran does not support an
invite-code signup flow.

**Example**:
```bash
curl https://your-pds.example.com/xrpc/com.atproto.server.describeServer
```

---

### com.atproto.server.createSession

Create a new session (login).

**Method**: `POST`
**Auth**: Not required

**Request Body**:
```json
{
  "identifier": "user.example.com",
  "password": "your-password"
}
```

**Response**:
```json
{
  "did": "did:web:example.com",
  "handle": "user.example.com",
  "accessJwt": "eyJ...",
  "refreshJwt": "eyJ..."
}
```

**Example**:
```bash
curl -X POST https://your-pds.example.com/xrpc/com.atproto.server.createSession \
  -H "Content-Type: application/json" \
  -d '{"identifier":"user.example.com","password":"secret"}'
```

---

### com.atproto.server.refreshSession

Refresh an expired access token.

**Method**: `POST`
**Auth**: Required (refresh token)

**Headers**:
```
Authorization: Bearer <refreshJwt>
```

**Request Body**: None. This endpoint is intentionally a bodyless `POST`; the refresh token is supplied only via the `Authorization` header.

**Deployment note**: This bodyless POST is valid XRPC traffic. Alteran normalizes `/xrpc/*` requests before Astro's SSR origin-check middleware so native and browser atproto clients do not hit Astro's form CSRF guard.

**Response**:
```json
{
  "did": "did:web:example.com",
  "handle": "user.example.com",
  "accessJwt": "eyJ...",
  "refreshJwt": "eyJ..."
}
```

**Example**:
```bash
curl -X POST https://your-pds.example.com/xrpc/com.atproto.server.refreshSession \
  -H "Authorization: Bearer <refreshJwt>"
```

---

### com.atproto.server.getSession

Get current session information.

**Method**: `GET`
**Auth**: Required

**Response**:
```json
{
  "did": "did:web:example.com",
  "handle": "user.example.com"
}
```

**Example**:
```bash
curl https://your-pds.example.com/xrpc/com.atproto.server.getSession \
  -H "Authorization: Bearer <accessJwt>"
```

---

### com.atproto.server.deleteSession

Delete current session (logout).

**Method**: `POST`
**Auth**: Required

**Response**: `200 OK` (empty body)

**Example**:
```bash
curl -X POST https://your-pds.example.com/xrpc/com.atproto.server.deleteSession \
  -H "Authorization: Bearer <accessJwt>"
```

---

## Repository Endpoints

### com.atproto.repo.describeRepo

Get repository information.

**Method**: `GET`
**Auth**: Not required

**Query Parameters**:
- `repo` (required): DID or handle

**Response**:
```json
{
  "did": "did:web:example.com",
  "handle": "user.example.com",
  "didDoc": { ... },
  "collections": ["app.bsky.feed.post", "app.bsky.actor.profile"],
  "handleIsCorrect": true
}
```

**Example**:
```bash
curl "https://your-pds.example.com/xrpc/com.atproto.repo.describeRepo?repo=did:web:example.com"
```

---

### com.atproto.repo.createRecord

Create a new record.

**Method**: `POST`
**Auth**: Required

**Request Body**:
```json
{
  "repo": "did:web:example.com",
  "collection": "app.bsky.feed.post",
  "record": {
    "text": "Hello, world!",
    "createdAt": "2025-10-02T23:00:00.000Z"
  }
}
```

**Response**:
```json
{
  "uri": "at://did:web:example.com/app.bsky.feed.post/3k...",
  "cid": "bafyrei..."
}
```

**Example**:
```bash
curl -X POST https://your-pds.example.com/xrpc/com.atproto.repo.createRecord \
  -H "Authorization: Bearer <accessJwt>" \
  -H "Content-Type: application/json" \
  -d '{
    "repo": "did:web:example.com",
    "collection": "app.bsky.feed.post",
    "record": {
      "text": "Hello, world!",
      "createdAt": "2025-10-02T23:00:00.000Z"
    }
  }'
```

---

### com.atproto.repo.getRecord

Get a specific record.

**Method**: `GET`
**Auth**: Not required

**Query Parameters**:
- `repo` (required): DID or handle
- `collection` (required): Collection NSID
- `rkey` (required): Record key

**Response**:
```json
{
  "uri": "at://did:web:example.com/app.bsky.feed.post/3k...",
  "cid": "bafyrei...",
  "value": {
    "text": "Hello, world!",
    "createdAt": "2025-10-02T23:00:00.000Z"
  }
}
```

**Example**:
```bash
curl "https://your-pds.example.com/xrpc/com.atproto.repo.getRecord?repo=did:web:example.com&collection=app.bsky.feed.post&rkey=3k..."
```

---

### com.atproto.repo.listRecords

List records in a collection.

**Method**: `GET`
**Auth**: Not required

**Query Parameters**:
- `repo` (required): DID or handle
- `collection` (required): Collection NSID
- `limit` (optional): Max records to return (default: 50)
- `cursor` (optional): Pagination cursor

**Response**:
```json
{
  "records": [
    {
      "uri": "at://did:web:example.com/app.bsky.feed.post/3k...",
      "cid": "bafyrei...",
      "value": { ... }
    }
  ],
  "cursor": "..."
}
```

**Example**:
```bash
curl "https://your-pds.example.com/xrpc/com.atproto.repo.listRecords?repo=did:web:example.com&collection=app.bsky.feed.post&limit=10"
```

---

### com.atproto.repo.putRecord

Update an existing record.

**Method**: `POST`
**Auth**: Required

**Request Body**:
```json
{
  "repo": "did:web:example.com",
  "collection": "app.bsky.feed.post",
  "rkey": "3k...",
  "record": {
    "text": "Updated text",
    "createdAt": "2025-10-02T23:00:00.000Z"
  }
}
```

**Response**:
```json
{
  "uri": "at://did:web:example.com/app.bsky.feed.post/3k...",
  "cid": "bafyrei..."
}
```

---

### com.atproto.repo.deleteRecord

Delete a record.

**Method**: `POST`
**Auth**: Required

**Request Body**:
```json
{
  "repo": "did:web:example.com",
  "collection": "app.bsky.feed.post",
  "rkey": "3k..."
}
```

**Response**: `200 OK` (empty body)

**Example**:
```bash
curl -X POST https://your-pds.example.com/xrpc/com.atproto.repo.deleteRecord \
  -H "Authorization: Bearer <accessJwt>" \
  -H "Content-Type: application/json" \
  -d '{
    "repo": "did:web:example.com",
    "collection": "app.bsky.feed.post",
    "rkey": "3k..."
  }'
```

---

### com.atproto.repo.uploadBlob

Upload a blob (image, video, etc.).

**Method**: `POST`
**Auth**: Required
**Content-Type**: `image/jpeg`, `image/png`, etc.

**Request Body**: Binary blob data

**Response**:
```json
{
  "blob": {
    "$type": "blob",
    "ref": {
      "$link": "bafyrei..."
    },
    "mimeType": "image/jpeg",
    "size": 123456
  }
}
```

**Example**:
```bash
curl -X POST https://your-pds.example.com/xrpc/com.atproto.repo.uploadBlob \
  -H "Authorization: Bearer <accessJwt>" \
  -H "Content-Type: image/jpeg" \
  --data-binary @image.jpg
```

---

### com.atproto.repo.applyWrites

Apply multiple write operations atomically.

**Method**: `POST`
**Auth**: Required

**Request Body**:
```json
{
  "repo": "did:web:example.com",
  "writes": [
    {
      "$type": "com.atproto.repo.applyWrites#create",
      "collection": "app.bsky.feed.post",
      "value": { ... }
    },
    {
      "$type": "com.atproto.repo.applyWrites#delete",
      "collection": "app.bsky.feed.post",
      "rkey": "3k..."
    }
  ]
}
```

**Response**: `200 OK`

---

## Sync Endpoints

### com.atproto.sync.getHead

Get the current head of the repository.

**Method**: `GET`
**Auth**: Not required

**Query Parameters**:
- `did` (required): Repository DID

**Response**:
```json
{
  "root": "bafyrei..."
}
```

---

### com.atproto.sync.getLatestCommit

Get the latest commit.

**Method**: `GET`
**Auth**: Not required

**Query Parameters**:
- `did` (required): Repository DID

**Response**:
```json
{
  "cid": "bafyrei...",
  "rev": "3k..."
}
```

---

### com.atproto.sync.getRepo

Export entire repository as CAR file.

**Method**: `GET`
**Auth**: Not required
**Response Type**: `application/vnd.ipld.car`

**Query Parameters**:
- `did` (required): Repository DID

**Response**: Binary CAR file

**Example**:
```bash
curl "https://your-pds.example.com/xrpc/com.atproto.sync.getRepo?did=did:web:example.com" \
  -o repo.car
```

---

### com.atproto.sync.getBlocks

Get specific blocks from the repository.

**Method**: `GET`
**Auth**: Not required
**Response Type**: `application/vnd.ipld.car`

**Query Parameters**:
- `did` (required): Repository DID
- `cids` (required): Comma-separated CIDs

**Response**: Binary CAR file with requested blocks

---

### com.atproto.sync.listBlobs

List all blobs in the repository.

**Method**: `GET`
**Auth**: Not required

**Query Parameters**:
- `did` (required): Repository DID

**Response**:
```json
{
  "cids": ["bafyrei...", "bafyrei..."]
}
```

---

### com.atproto.sync.listRepos

List all repositories on this PDS.

**Method**: `GET`
**Auth**: Not required

**Response**:
```json
{
  "repos": [
    {
      "did": "did:web:example.com",
      "head": "bafyrei...",
      "rev": "3k..."
    }
  ]
}
```

---

### com.atproto.sync.subscribeRepos

Subscribe to repository events via WebSocket.

**Method**: `GET` (WebSocket upgrade)
**Auth**: Not required

**Query Parameters**:
- `cursor` (optional): Start from specific sequence number

**WebSocket Frames**:

Frames are binary WebSocket messages containing a DAG-CBOR header followed by a
DAG-CBOR payload. The sequencer durably stores the encoded event before live
broadcast, and cursor replay sends those same bytes back to subscribers.

Alteran currently emits and replays `#commit`, `#identity`, and `#account`
events. It does not emit `#sync`; that event is reserved for repository reset
state and requires `blocks` and `rev`.

1. **Info Frame** (too-old cursor):
```json
{
  "op": 1,
  "t": "#info",
  "name": "OutdatedCursor",
  "message": "Consumer is too far behind"
}
```

2. **Commit Frame** (on write):
```cbor
{
  "op": 1,
  "t": "#commit",
  "seq": 123,
  "rebase": false,
  "tooBig": false,
  "repo": "did:web:example.com",
  "commit": <CID>,
  "rev": "3k...",
  "since": "3j...",
  "blocks": <CAR bytes>,
  "ops": [
    {
      "action": "create",
      "path": "app.bsky.feed.post/3k...",
      "cid": <CID>
    }
  ],
  "blobs": [],
  "time": "2025-10-02T23:00:00.000Z"
}
```

**Example**:
```bash
wscat -c "wss://your-pds.example.com/xrpc/com.atproto.sync.subscribeRepos"
```

---

## Identity Endpoints

### com.atproto.identity.resolveHandle

Resolve a handle to a DID.

**Method**: `GET`
**Auth**: Not required

**Query Parameters**:
- `handle` (required): Handle to resolve

**Response**:
```json
{
  "did": "did:web:example.com"
}
```

**Example**:
```bash
curl "https://your-pds.example.com/xrpc/com.atproto.identity.resolveHandle?handle=user.example.com"
```

---

### com.atproto.identity.updateHandle

Update the repository handle.

**Method**: `POST`
**Auth**: Required

**Request Body**:
```json
{
  "handle": "newhandle.example.com"
}
```

**Response**: `200 OK`

---

## Rate Limiting

All write endpoints are rate-limited per IP address.

**Default Limits**:
- Write operations: 60 requests/minute
- Blob uploads: 30 requests/minute

**Rate Limit Headers**:
```
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 45
X-RateLimit-Reset: 1696291200
```

**Rate Limit Exceeded Response** (429):
```json
{
  "error": "RateLimitExceeded",
  "message": "Too many requests. Try again in 30 seconds."
}
```

---

## Health Endpoints

### GET /health

Check service health.

**Response**:
```json
{
  "status": "healthy",
  "timestamp": "2025-10-02T23:00:00.000Z",
  "checks": {
    "database": { "status": "ok" },
    "storage": { "status": "ok" }
  }
}
```

### GET /ready

Check if service is ready to accept requests.

**Response**: `200 OK` or `503 Service Unavailable`

---

## CORS

CORS is configured per environment:
- **Development**: `*` (all origins)
- **Production**: Specific origins only (set via `PDS_CORS_ORIGIN`)

---

## SDK Examples

### JavaScript/TypeScript

```typescript
import { AtpAgent } from '@atproto/api';

const agent = new AtpAgent({
  service: 'https://your-pds.example.com'
});

// Login
await agent.login({
  identifier: 'user.example.com',
  password: 'secret'
});

// Create post
await agent.com.atproto.repo.createRecord({
  repo: agent.session.did,
  collection: 'app.bsky.feed.post',
  record: {
    text: 'Hello, world!',
    createdAt: new Date().toISOString()
  }
});

// List posts
const { data } = await agent.com.atproto.repo.listRecords({
  repo: agent.session.did,
  collection: 'app.bsky.feed.post'
});
```

---

## See Also

- [AT Protocol Specification](https://atproto.com/specs/atp)
- [Lexicon Schemas](https://github.com/bluesky-social/atproto/tree/main/lexicons)
- [Security Documentation](./SECURITY.md)
