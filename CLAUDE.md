# CLAUDE.md

Guidance for Claude (and other agents) working in this repository. Read this before writing code. Rules are stated directly, each with a one-line **Why** so you can judge edge cases instead of mechanically following them.

If a rule conflicts with an explicit user instruction in the current conversation, the user wins.

---

## 1. Core principles

**Functional first.** Pure functions over classes. Pass dependencies as arguments, return new values, avoid hidden state. **Why:** easier to test, easier to reason about, easier to compose. Classes are allowed only where the framework demands them — the `Sequencer` Durable Object is the documented exception.

**Group by function, not by type.** Colocate things that change together. A feature owns its handler, its service code, its types, and its tests. **Why:** type-based silos (`controllers/`, `models/`, `dtos/`) scatter a single change across the tree and obscure ownership.

**No abbreviations in identifiers.** `request` not `req`, `response` not `res`, `database` not `db`, `error` not `err`, `index` not `idx`. **Why:** abbreviations save three keystrokes and cost every future reader a re-parse. Existing directory names (`src/db/`, `src/lib/`) stay as-is for stability — the rule is about new code.

**Types and structs whenever possible.** Model every meaningful value with a `type`. Prefer discriminated unions to boolean flags or stringly-typed status fields. **Why:** the compiler enforces invariants the runtime would otherwise discover with a 3 a.m. page.

**Finite state machines for stateful logic.** Anything with distinct states and transitions — auth flows, session lifecycle, sync status, upload pipelines, retry policies — gets modeled as an FSM. **Why:** FSMs make every state exhaustive, every transition explicit, and illegal states unrepresentable. Encode as a discriminated union plus a pure `transition(state, event): State` function:

```ts
type SessionState =
  | { tag: "anonymous" }
  | { tag: "authenticating"; handle: string }
  | { tag: "authenticated"; did: string; accessJwt: string; refreshJwt: string }
  | { tag: "refreshing"; did: string }
  | { tag: "expired"; did: string };

type SessionEvent =
  | { tag: "login"; handle: string }
  | { tag: "loginSucceeded"; did: string; accessJwt: string; refreshJwt: string }
  | { tag: "tokenExpired" }
  | { tag: "refreshSucceeded"; accessJwt: string; refreshJwt: string }
  | { tag: "refreshFailed" }
  | { tag: "logout" };

function transition(state: SessionState, event: SessionEvent): SessionState { /* ... */ }
```

Reach for a library (e.g. XState) only when you need parallel regions, history, or hierarchical states. Hand-roll otherwise.

**Max 500 lines per file. Hard ceiling.** Split by responsibility well before that — most files should be under 200 lines. **Why:** small files force clear seams and make code reviewable in one screen.

**Many small files over a few large ones.** One exported concept per file when reasonable. **Why:** easier to grep, easier to move, easier to delete.

**No premature abstraction.** Three duplications before a helper. Two similar functions are not a pattern. **Why:** the wrong abstraction is more expensive than duplication.

**Comments explain WHY, not WHAT.** Good names handle the WHAT. Only write a comment if the reason is non-obvious — a hidden constraint, a subtle invariant, a workaround for a known bug. **Why:** comments that paraphrase code rot the moment the code changes.

---

## 2. TypeScript

**`strict: true` always.** No loosening of `strict`, `noImplicitAny`, or `strictNullChecks`. **Why:** the whole point of TypeScript is the guarantees `strict` provides.

**No `any`. No non-null assertions (`!`) outside test fixtures.** Reach for `unknown` and narrow. **Why:** `any` poisons inference transitively; `!` is a lie the compiler is forced to believe.

**Prefer `type` aliases for data; `interface` only when declaration merging is required.** **Why:** `type` composes cleanly with unions, intersections, and conditionals; `interface` is for extension points (rare here).

**Discriminated unions over flags.** A `{ tag: "..." }` field is the cheap, mechanical way to model alternative shapes. **Why:** the compiler can narrow exhaustively; booleans cannot.

**`readonly` by default on struct fields and arrays.** Mutation is a choice, not a default. **Why:** shared mutable state is the source of most concurrency bugs.

**No `enum`.** Use `as const` object literals plus a derived union type:

```ts
const Role = { Admin: "admin", Member: "member" } as const;
type Role = (typeof Role)[keyof typeof Role];
```

**Why:** TS `enum`s emit runtime code, allow accidental numeric coercion, and don't tree-shake well.

**Narrow at the boundary, trust internally.** Parse incoming JSON / form data / headers with a guard (zod, hand-rolled type predicate, etc.) once; downstream code receives the parsed struct. **Why:** validation everywhere is noise; validation at boundaries is correctness.

---

## 3. Bun

**Use Bun's native test runner.** `import { describe, it, expect } from "bun:test"`. **Why:** it's already installed, fast, and matches the rest of the toolchain.

**`bun run <script>` and `bunx <tool>`.** Never `npm`, `npx`, `pnpm`, or `yarn`. **Why:** one toolchain, one lockfile, one source of truth.

**Prefer Bun's built-in APIs where the Workers runtime allows.** `Bun.file`, `Bun.password`, `Bun.hash` for local scripts; obviously not inside the Worker bundle. **Why:** fewer dependencies, faster startup.

**Commit `bun.lock`. Never hand-edit it.** **Why:** it's the reproducible-build contract.

---

## 4. Cloudflare Workers

**Workers is not Node.** No `fs`, no `child_process`, no `process.*` (beyond what's polyfilled), no long-lived timers, no background work after the response. **Why:** the runtime kills you for it. If you find yourself reaching for a Node-only API, find a Web-Platform equivalent or move the work to a script under `scripts/`.

**D1: parameterized queries, always.** No string concatenation into SQL. Use Drizzle for schema and queries. **Why:** SQL injection, query plan thrash, and unreadable code — pick any three.

**D1 has no interactive transactions.** Use batched statements (`db.batch([...])`). Plan writes accordingly. **Why:** D1 implements transactions only over a single batch RPC.

**R2: stream blobs.** Pipe `request.body` and response bodies through; never materialize a large object in memory unless you have a hard upper bound on size. **Why:** Workers' memory ceiling will end the request before you find out.

**Durable Objects: one DO per coordination domain.** Alteran's `Sequencer` exists because the firehose needs a single writer. Don't proliferate DOs casually — they're expensive in latency and operational surface area. **Why:** DOs serialize requests by design; that's their value and their cost.

**DO storage is strongly consistent. D1 is not.** Pick the right tool for the consistency requirement. **Why:** misplacing the line here is a source of subtle, intermittent bugs.

**Secrets via `wrangler secret put`.** Never commit `.env`, `credentials.json`, or anything resembling a token. **Why:** git history is forever; rotation is painful.

**Honor `request.signal`.** On long-running fetches or streaming work, listen for cancellation and abort. **Why:** the client gave up; you should too.

---

## 5. Error handling

**Throw at the boundary, return at the core.** Handlers translate caught errors into XRPC error responses. Internal functions return typed Results (or throw, consistently within their module) when failure is an expected outcome. **Why:** throws are great for exceptional flow but terrible as a primary signaling mechanism — typed results document the contract.

**Structured errors with stable codes.** Every thrown error carries a stable string `code` so the XRPC layer can map it to the right response. See `src/lib/errors.ts` and `src/lib/auth-errors.ts` for the existing taxonomy — extend that, don't reinvent. **Why:** clients depend on these codes; renaming them is a breaking change.

**Never swallow errors silently.** Log via `src/lib/logger.ts`, include the request id when available. **Why:** silent failure is the worst failure mode.

**`try { } catch { /* ignore */ }` is a smell.** If you genuinely intend to ignore an error, write a one-line comment explaining why. **Why:** future-you needs to know whether the silence is deliberate or accidental.

---

## 6. Testing

**`bun test` runs everything.** Tests live in `tests/*.test.ts`. **Why:** one command, predictable layout.

**One behavior per `it()`.** Describe-block names match the module under test. **Why:** when a test fails, you should know what regressed from the failure name alone.

**Integration tests stay gated behind `RUN_APP_TESTS=true`.** Don't unconditionally enable them — they boot the full app and are slow. **Why:** fast feedback for unit tests, deliberate opt-in for integration runs.

**Test names describe behavior, not implementation.** `"rejects expired bearer token"` ✅. `"calls verifyJwt with expired claim"` ❌. **Why:** behavior names survive refactors; implementation names don't.

**Hit the real D1 in DB tests; do not mock the database.** Use Miniflare's local D1 or the wrangler-provisioned local DB. **Why:** mocked schemas drift from real schemas; mocked tests pass while production breaks.

---

## 7. This codebase (alteran)

A single-user ATProto Personal Data Server on Cloudflare Workers, packaged as an Astro integration.

### Stack

- **TypeScript 5** (strict)
- **Bun** as the package manager and test runner
- **Astro 5** with `@astrojs/cloudflare`
- **Hono 4** for XRPC routing
- **Drizzle ORM** over **Cloudflare D1**
- **Cloudflare R2** for blob storage
- **One Durable Object** (`Sequencer`) for the firehose

### Directory map

- `src/handlers/` — XRPC and HTTP endpoints. One file per endpoint or tight namespace (e.g. `xrpc.repo.core.ts`, `xrpc.server.createSession.ts`). Handlers are thin: parse, authenticate, delegate to a service, format the response.
- `src/services/` — Domain logic. `repo-manager.ts`, `r2-blob-store.ts`, `car.ts`. Services own the business rules; handlers own the protocol.
- `src/lib/` — Small, single-concept utilities. `jwt.ts`, `did-document.ts`, `errors.ts`, `auth-errors.ts`, `logger.ts`, `handle.ts`. If a file in `lib/` starts to grow, split it.
- `src/db/` — Drizzle schema and generated migrations.
- `src/worker/` — Worker entry runtime and the `Sequencer` Durable Object.
- `src/middleware.ts` — CORS and request logging.
- `tests/` — `bun:test` files.
- `scripts/` — One-off operational scripts (run with `bun run scripts/<name>.ts`).
- `iac/` — Alchemy infrastructure-as-code.

### Commands

| Task | Command |
|---|---|
| Dev server | `bun run dev` |
| Build | `bun run build` |
| Deploy (build + wrangler) | `bun run deploy` |
| Generate migrations | `bun run db:generate` |
| Apply migrations locally | `bun run db:apply:local` |
| Apply migrations to prod D1 | `bun run db:apply` |
| Reset local DB and migrations | `bun run db:reset:local` |
| Set up secrets | `bun run secrets:setup` |
| IaC plan / deploy / destroy | `bun run iac:plan` / `bun run iac:deploy` / `bun run iac:destroy` |
| Tests | `bun test` |
| Integration tests | `RUN_APP_TESTS=true bun test` |

### Conventions

**Adding an XRPC endpoint:**
1. New file in `src/handlers/`, named `xrpc.<namespace>.<method>.ts`.
2. Export an async function that takes the Astro `APIContext` (or Hono `Context`, depending on the surrounding wiring).
3. Authenticate, parse the body once, delegate to a service in `src/services/`.
4. Translate service errors via the codes in `src/lib/errors.ts` / `src/lib/auth-errors.ts`.
5. Wire it into the Hono app where its siblings are mounted.

**Adding a table:**
1. Edit `src/db/schema.ts` (add the table, indexes, and any relations).
2. `bun run db:generate` — Drizzle writes a new file under `migrations/`.
3. Commit the generated migration alongside the schema change. Do not edit generated migrations after they've been applied to any environment.

**Adding a service:**
- New file in `src/services/`. Export pure functions where possible; group related functions in one file (the file is the module boundary).
- No classes unless you need instance state that genuinely belongs together (rare).

**Adding a utility:**
- One concept per file in `src/lib/`. If the utility is only used in one place, put it next to its caller instead.

---

## When in doubt

- Prefer the smaller change.
- Prefer the more typed representation.
- Prefer the explicit state machine to the implicit one.
- Prefer the existing pattern to inventing a new one.
- Ask the user before doing anything destructive or hard to reverse.
