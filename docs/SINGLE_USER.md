Single‑User PDS: Quick Start

This is the minimal, one‑time checklist to run a single‑user PDS on Cloudflare Workers.

Read [`SINGLE_USER_BOUNDARIES.md`](SINGLE_USER_BOUNDARIES.md) before exposing a
deployment publicly. It explains which public account, moderation, report,
recovery, and ToS flows are deliberate single-user non-goals and what operators
must configure instead.

1) One‑Time Setup
- Point your domain to the Worker route so `/.well-known/*` is served by this app.
- Set secrets (once per account):
  - `wrangler secret put PDS_DID`
  - `wrangler secret put PDS_HANDLE`
  - `wrangler secret put USER_PASSWORD`
  - `wrangler secret put REFRESH_TOKEN`
  - `wrangler secret put REFRESH_TOKEN_SECRET`
  - `wrangler secret put REPO_SIGNING_KEY`
- Optional public policy links:
  - `PDS_LINK_TOS`
  - `PDS_LINK_PRIVACY`

  OAuth client metadata/JWKS are fetched dynamically from public HTTPS URLs
  using hardened fetch checks.

  Or run the bootstrap script to generate everything and print commands:

  ```bash
  bun run scripts/setup-secrets.ts --env production --did did:web:example.com --handle user.example.com
  ```
- Apply D1 migrations:
  - `wrangler d1 migrations apply pds`

2) Build & Deploy
- `bun install`
- `bun run deploy`

3) Quick Smoke
- `curl https://<your-host>/health`
- Login: `POST /xrpc/com.atproto.server.createSession` with `{ "identifier": "user", "password": "<USER_PASSWORD>" }`
- Create record: `POST /xrpc/com.atproto.repo.createRecord`
- Get record: `GET /xrpc/com.atproto.repo.getRecord`
- Check CAR root: `GET /xrpc/com.atproto.sync.getHead` matches root in `GET /xrpc/com.atproto.sync.getRepo`

Optional: Firehose
- Connect a WebSocket client to `wss://<your-host>/xrpc/com.atproto.sync.subscribeRepos`
- Perform two writes; you should see `#commit` frames with increasing `seq`
