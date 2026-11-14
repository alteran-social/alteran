# Configuration Management

These examples describe the Alteran repository's standalone deployment.
Applications using the integration must configure their own Worker and
resources.

Alteran reads runtime settings from the current Worker's request Env. The fields
listed under Secret Store below support that binding type; other settings must
be Worker strings. Alteran does not fall back to Astro's global env accessor or
`process.env`. Before upgrading, expose any Alteran credentials previously
available only through Astro as Worker vars, secrets or supported Secret Store
bindings. Verify the intended session key and D1 state before rollout: a missing
Worker binding causes sessions to use the D1 key, which may differ from the old
one.

An explicitly configured blank credential is invalid, including a blank Secret
Store value; omit an optional credential instead. Env resolution retains the
leading and trailing whitespace of nonblank values; individual key formats may
define their own parsing rules.

Alteran does not override the host application's Astro env accessor. A host app
using `astro:env/server` continues to follow its Astro adapter's behavior; it
must resolve any Secret Store binding it uses in its own code.

The Worker wrapper passes its captured Env to middleware through request-local
context. Enable Cloudflare's `nodejs_compat` compatibility flag. If a custom
integration invokes Alteran's `onRequest` middleware without that wrapper, it
must set `locals.env` to the current request's Worker Env explicitly. Missing
request context is an error; middleware does not fall back to a global Env. The
integration respects an existing Cloudflare adapter entrypoint alias; an app
with its own alias or entrypoint must compose `createPdsFetchHandler` or provide
`locals.env` before invoking Alteran middleware. Use the same installed Alteran
package for the integration and wrapper. If a bundle duplicates their
request-context modules, middleware cannot see the wrapper's captured Env; it
uses `locals.env` if supplied and fails closed when that is absent. A caller
supplying `locals.env` must provide the correct Env for each request.

Declared Alteran Env fields can be own or inherited properties, including
non-enumerable properties; getters are evaluated against the supplied Env. The
Astro `SESSION` binding is also captured. Other application-specific fields must
be own enumerable properties to be copied.

## Environment Setup

This PDS has separate dev, staging and production configurations. Astro selects
an environment at build time; a later `wrangler deploy --env` does not retarget
the generated build. Follow [Deployment](DEPLOYMENT.md) for the guarded
production workflow and named-environment builds.

## Identity and credentials

Set `PDS_DID`, `PDS_HANDLE` and `PDS_HOSTNAME` in the selected environment's
`vars`. Replace the checked-in production identity with your own if needed.
These settings are public identity values and can appear in protocol responses;
do not put credentials in them.
Verify that same-name remote secrets do not conflict; the local check cannot
inspect those secrets. See [Deployment](DEPLOYMENT.md) before deployment.

| Credential           | Use                                                                   |
| -------------------- | --------------------------------------------------------------------- |
| `USER_PASSWORD`      | Login password                                                        |
| `REPO_SIGNING_KEY`   | secp256k1 key for commits and service authentication                  |
| `SESSION_JWT_SECRET` | Optional session signing key; D1 generates and stores one when absent |

Older-format JWTs are no longer accepted; clients using them must authenticate
again. See [Deployment](DEPLOYMENT.md) for mixed-version rollout guidance.

**Generate credentials for a new deployment:**

```bash
# Prints sensitive credentials and Wrangler commands
deno run -A scripts/setup-secrets.ts --env production --did did:web:example.com --handle user.example.com --hostname user.example.com

# After verifying the intended account and Worker
deno run -A npm:wrangler secret put USER_PASSWORD --env production
deno run -A npm:wrangler secret put REPO_SIGNING_KEY --env production
deno run -A npm:wrangler secret put SESSION_JWT_SECRET --env production # optional
```

## Using Cloudflare Secret Store (optional)

Instead of Wrangler Secrets, you may bind secrets from Cloudflare Secret Store.
This repo now supports both. Bind each secret you want to source from Secret
Store via `secrets_store_secrets` in `wrangler.jsonc`:

```jsonc
{
  // ...
  "secrets_store_secrets": [
    {
      "binding": "USER_PASSWORD",
      "secret_name": "user_password",
      "store_id": "<your-store-id>"
    },
    {
      "binding": "SESSION_JWT_SECRET",
      "secret_name": "session_jwt_secret",
      "store_id": "<your-store-id>"
    },
    {
      "binding": "REPO_SIGNING_KEY",
      "secret_name": "repo_signing_key",
      "store_id": "<your-store-id>"
    }
  ]
}
```

Notes:

- Bindings can use the same names as the existing env vars. Only one source
  should be configured per secret (Wrangler Secret OR Secret Store binding).
- Secret Store is supported for `PDS_DID`, `PDS_HANDLE`, `USER_PASSWORD`,
  `SESSION_JWT_SECRET`, `REPO_SIGNING_KEY`, `PDS_PLC_ROTATION_KEY`, and
  `PDS_SPACE_KEM_KEY`. In the repository deployment, the first two must instead
  be production vars to pass the deploy preflight. `PDS_HOSTNAME` must be a
  string, not a Secret Store binding.
- Alteran resolves its request's supported Secret Store bindings when reading
  them.

## Optional Configuration

These can be set as environment variables in
[`wrangler.jsonc`](https://github.com/alteran-social/alteran/blob/main/wrangler.jsonc)
or as secrets:

| Variable                 | Default                    | Description                                                                                           |
| ------------------------ | -------------------------- | ----------------------------------------------------------------------------------------------------- |
| `PDS_ALLOWED_MIME`       | `image/jpeg,image/png,...` | Comma-separated MIME types                                                                            |
| `PDS_MAX_BLOB_SIZE`      | `5242880` (5MB)            | Max blob size in bytes                                                                                |
| `PDS_MAX_JSON_BYTES`     | `1048576` (1MB)            | Max JSON body size                                                                                    |
| `PDS_RATE_LIMIT_PER_MIN` | `1000`                     | Records written per minute (an `applyWrites` call counts once per write, so keep this at 200 or more) |
| `PDS_CORS_ORIGIN`        | `*` (dev), specific (prod) | Allowed CORS origins                                                                                  |
| `PDS_SEQ_WINDOW`         | `512`                      | Firehose sequence window                                                                              |
| `PDS_HOSTNAME`           | -                          | Public hostname                                                                                       |
| `PDS_ACCESS_TTL_SEC`     | `3600` (1 hour)            | Access token TTL                                                                                      |
| `PDS_REFRESH_TTL_SEC`    | `2592000` (30 days)        | Refresh token TTL                                                                                     |

## Configuration Validation

The PDS validates required identity configuration on startup and reports
warnings:

```typescript
// Automatic validation in src/_worker.ts
validateConfigOrThrow(env);
```

**Validation checks:**

- Required identity values are present
- Warns about wildcard CORS in production, invalid DID or handle formats,
  missing signing keys, and nonpositive numeric values

## Cloudflare Security Rules

`com.atproto.server.refreshSession` is a valid bodyless `POST`. Production
deployments must allow this request shape through to the XRPC handler:

```txt
(http.request.method eq "POST" and http.request.uri.path eq "/xrpc/com.atproto.server.refreshSession")
```

Astro's SSR origin-check middleware rejects unsafe requests with no `Origin`
header before project middleware runs. Alteran normalizes `/xrpc/*` requests at
the Worker entrypoint so bearer-token XRPC clients can send bodyless POSTs
without tripping Astro's form CSRF guard.

If Cloudflare WAF/API Shield also protects the deployment, keep any exception
narrow to the expression above. This exception is not configured in
`wrangler.jsonc`; Wrangler only manages the Worker deployment and bindings.

## Environment-Specific Settings

See the repository's
[`wrangler.jsonc`](https://github.com/alteran-social/alteran/blob/main/wrangler.jsonc)
for environment-specific configurations:

- **Development**: Relaxed CORS, larger blob limits, local D1/R2
- **Staging**: Production-like settings, separate D1/R2 instances
- **Production**: Strict CORS, production D1/R2, observability enabled

Debugging & storage

- D1 schema/migrations: generated with Drizzle Kit into `drizzle/`. Generate
  with `deno run -A npm:drizzle-kit generate`.
- Apply schema locally:
  `deno run -A npm:wrangler d1 migrations apply ALTERAN_DB --env dev --local`.
- Bootstrap route (alt): `POST /debug/db/bootstrap` creates a minimal `record`
  table.
- Insert a test record: `POST /debug/record` with
  `{ "uri": "at://did:example/app.bsky.feed.post/123", "json": {"msg":"hi"} }`.
- Get a record: `GET /debug/record?uri=at://did:example/app.bsky.feed.post/123`.
- Run GC: `POST /debug/gc/blobs` removes eligible unreferenced blob metadata.

XRPC surface

- `GET /xrpc/com.atproto.server.describeServer`
- `POST /xrpc/com.atproto.server.createSession` (returns JWTs)
- `POST /xrpc/com.atproto.server.refreshSession`
- `GET /xrpc/com.atproto.repo.getRecord?uri=...` (reads from D1 `record` table)
  or `repo+collection+rkey`
- `POST /xrpc/com.atproto.repo.createRecord` (auth required)
- `POST /xrpc/com.atproto.repo.putRecord` (auth required)
- `POST /xrpc/com.atproto.repo.deleteRecord` (auth required)
- `POST /xrpc/com.atproto.repo.uploadBlob` (auth + MIME allowlist)
  - Stores blob metadata in `blob` table (`cid`=sha256 b64url, `mime`, `size`)
  - Blob references inside records tracked by R2 key; deleting a record drops
    usage and GC can reclaim orphaned objects

Sync (minimal JSON variants)

- `GET /xrpc/com.atproto.sync.getHead` → `{ root, rev }`
- `GET /xrpc/com.atproto.sync.getRepo.json?did=<did>` →
  `{ did, head, rev, records: [{uri,cid,value}] }`
- `GET /xrpc/com.atproto.sync.getCheckout.json?did=<did>` → same as above
- `GET /xrpc/com.atproto.sync.getBlocks.json?cids=<cid1,cid2>` →
  `{ blocks: [{cid,value}] }`

Sync (CAR v1)

- `GET /xrpc/com.atproto.sync.getRepo?did=<did>` → `application/vnd.ipld.car`
  snapshot
- `GET /xrpc/com.atproto.sync.getCheckout?did=<did>` → same as above
- `GET /xrpc/com.atproto.sync.getBlocks?cids=<cid1,cid2>` →
  `application/vnd.ipld.car` with requested blocks
  - Blocks are DAG-CBOR encoded; CIDs are CIDv1 (dag-cbor + sha2-256)

Firehose (WebSocket)

- `GET /xrpc/com.atproto.sync.subscribeRepos` upgrades to WebSocket.
- On writes, the worker POSTs a small commit frame to the `Sequencer` Durable
  Object, which broadcasts to all subscribers.
- Frames (subject to change):
  - `{"type":"hello","now":<ms>}` once on connect
  - `{"type":"commit","did":"...","commitCid":"...","rev":<n>,"ts":<ms>}` on
    each write

Blob storage

- Keys are content-addressed: `blobs/by-cid/<sha256-b64url>`; upload response
  `$link` equals this key.
- Allowed MIME types via `PDS_ALLOWED_MIME` (CSV). Size limit via
  `PDS_MAX_BLOB_SIZE` (bytes).

Secrets & config (Wrangler)

- Configure `PDS_DID`, `PDS_HANDLE`, and `PDS_HOSTNAME` in environment vars.
- Configure `USER_PASSWORD` and `REPO_SIGNING_KEY` as secrets. A
  `SESSION_JWT_SECRET` secret is optional when D1 is available.
- Optional:
  - `PDS_ALLOWED_MIME`, `PDS_MAX_BLOB_SIZE`, `PDS_MAX_JSON_BYTES`,
    `PDS_RATE_LIMIT_PER_MIN`, `PDS_CORS_ORIGIN`
- Durable Objects: ensure binding for `Sequencer` exists and migration tag added
  (see `wrangler.jsonc`).

Identity (DID)

- Configure the DID, handle and hostname vars for the deployment's identity.
- Host `/.well-known/atproto-did` on the handle domain with the DID value.
