Single‑User PDS: Quick Start

This is the minimal, one‑time checklist to run a single‑user PDS on Cloudflare
Workers.

Read [`SINGLE_USER_BOUNDARIES.md`](SINGLE_USER_BOUNDARIES.md) before exposing a
deployment publicly. It explains which public account, moderation, report,
recovery, and ToS flows are deliberate single-user non-goals and what operators
must configure instead.

1. One‑Time Setup

- Point your domain to the Worker route so `/.well-known/*` is served by this
  app.
- Set the intended `PDS_DID`, `PDS_HANDLE` and `PDS_HOSTNAME` in the named
  production vars in `wrangler.jsonc`. Check that same-name remote secrets do
  not conflict; preflight cannot inspect them.
- After verifying the account and Worker, set credentials:
  - `deno run -A npm:wrangler secret put USER_PASSWORD --env production`
  - `deno run -A npm:wrangler secret put REPO_SIGNING_KEY --env production`
  - Optional:
    `deno run -A npm:wrangler secret put SESSION_JWT_SECRET --env production`.
    If absent, a session key is generated in D1.
- Optional public policy links:
  - `PDS_LINK_TOS`
  - `PDS_LINK_PRIVACY`

  OAuth client metadata/JWKS are fetched dynamically from public HTTPS URLs
  using hardened fetch checks.

  Or run the bootstrap script to generate credentials and print commands and
  sensitive values:

  ```bash
  deno run -A scripts/setup-secrets.ts --env production --did did:web:example.com --handle user.example.com --hostname user.example.com
  ```
- After verifying the account, database and backup, apply D1 migrations:
  - `deno run -A npm:wrangler d1 migrations apply ALTERAN_DB --env production --remote`

2. Build & Deploy

- `deno install`
- `deno task deploy`

3. Quick Smoke

- `curl https://<your-host>/health`
- Login: `POST /xrpc/com.atproto.server.createSession` with
  `{ "identifier": "user", "password": "<USER_PASSWORD>" }`
- Create record: `POST /xrpc/com.atproto.repo.createRecord`
- Get record: `GET /xrpc/com.atproto.repo.getRecord`
- Check CAR root: `GET /xrpc/com.atproto.sync.getHead` matches root in
  `GET /xrpc/com.atproto.sync.getRepo`

Optional: Firehose

- Connect a WebSocket client to
  `wss://<your-host>/xrpc/com.atproto.sync.subscribeRepos`
- Perform two writes; you should see `#commit` frames with increasing `seq`
