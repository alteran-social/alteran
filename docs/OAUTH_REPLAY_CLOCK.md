# OAuth replay clock operations

OAuth proof and client-assertion replay checks use a single nondecreasing clock
stored in D1. Admission and cleanup run against the primary database in atomic
batches. Migration `0024` creates and seeds the clock, and migration `0027`
creates the replay-expiry index. Migration `0031` adds confidential-client key
binding provenance. Apply all three and their intervening migrations before
deploying the new OAuth handlers. A missing or invalid clock causes
replay checks to fail closed. Validate index creation time and disk capacity on
a representative copy of the target database before the cutover.

These paths use `D1Database` directly, without a D1 session; Cloudflare states
that [queries without the Sessions API run on the primary](https://developers.cloudflare.com/d1/best-practices/read-replication/).
Do not switch these authorization reads to an arbitrary replica session.

## Upgrading an existing service

Older Workers can delete replay markers too early and can perform OAuth effects
without the shared clock. Do not serve old and new versions concurrently:

1. Stop all old Workers that can process OAuth or DPoP requests or run replay
   cleanup, and wait for their in-flight requests and cleanup jobs to finish.
2. Establish a safe cutoff for proofs and confidential-client assertions that
   old Workers could have accepted without a retained marker. A fixed waiting
   period is insufficient unless the maximum lead of every old Worker clock over
   D1 time is known. Cloudflare's published documentation does not establish
   such a bound. Do not resume service until an independently verified cutoff
   or another complete credential fence is in place.
3. Apply migrations through `0031`, deploy the new code, and prevent rollback to an old
   Worker while the new replay state is in use.

Rotating DPoP nonces alone is not a complete cutoff: confidential-client
assertions do not contain those nonces. Legacy replay markers are retained by
the new cleanup until their recorded proof or assertion can no longer be valid.
Malformed markers with unknown expiry are retained for investigation.

Migration `0031` adds an explicit version for confidential-client key bindings.
New authorizations bind the thumbprint of the verified public key, rather than
trusting its `kid`. Previously issued confidential-client authorizations,
sessions, and access tokens lack that version and must reauthorize; public
clients are unaffected. The key is verified against the fetched client JWKS at
request verification time, so a later remote JWKS change cannot be atomic with
the D1 transaction. Fence old Workers before permitting new authorization.

Authorization-code consumption, token-row creation, and replay claims commit
as one D1 batch. Refresh rotation likewise commits its token, session, and
proof updates together. A response can still be lost after a successful commit:
the code cannot be reused, and an authenticated retry of a rotated refresh
token with a fresh proof revokes that session. The client then needs a new
authorization. Database errors, mismatched bindings, and stale concurrent
snapshots do not revoke a session.

Explicit revocation with an access token requires the current access JTI and
scope. A superseded access token is a successful no-op. A bound older refresh
token can revoke its grant. If rotation changes the authenticated session
snapshot before the revocation batch, that revocation is also a no-op.
DPoP and confidential-client assertion claims are committed with revocation.
Legacy `com.atproto.server.deleteSession` accepts only unbound legacy refresh
tokens; OAuth clients use `/oauth/revoke` with their proof and client binding.

The D1 clock is authoritative at transaction commit. Workers also check proof,
assertion, grant, and token windows immediately before each token transaction
and before returning a token response; a delayed committed rotation can thus
require reauthorization even when its response is withheld. A Worker clock
that jumps forward after its last sample cannot retroactively undo a D1
commit, including an authenticated replay-triggered revocation. Monitor clock
health and account for this boundary when deciding the acceptable clock skew.

OAuth form bodies are limited to 1 MiB and 16,384 delivered stream chunks. A
request fragmented beyond that chunk count is rejected even if it is smaller
than the byte limit; clients and intermediaries should avoid extreme
fragmentation. Stored PAR, consent, and authorization-code snapshots are
bounded separately; oversized legacy snapshots must be restarted.

OAuth client metadata and JWKS fetches validate DNS before connecting, but the
checked address is not pinned to the later connection. Before production
rollout, independently verify an outbound network boundary that prevents
private-address access even if DNS changes, or replace this fetch path with a
gateway that enforces the destination at connection time. The DNS precheck by
itself does not establish that boundary.

## Restoring a database

Restoring D1 can roll back both the clock and replay markers, as well as OAuth
session revocations. Keep OAuth and DPoP traffic stopped during recovery. Do
not reset the clock or resume an old Worker as a recovery shortcut. Establish
a separate recovery procedure that fences pre-restore proofs and assertions
and accounts for restored session and revocation state before resuming traffic.

A database clock that jumps forward can cause valid requests to be rejected
until real time catches up. Moving the stored clock backwards would re-enable
previously expired proofs and is prohibited.

## Retention and cleanup

Each accepted proof can remove at most one old marker through the indexed
expiry range. The cutoff uses the signed proof time and D1 clock conservatively,
so markers may remain for several minutes after their validity window. This
amortized cleanup does not drain a pre-existing backlog when traffic is idle.
Provide a reliably awaited scheduler that runs the bounded 512-row sweep until
the backlog is controlled, and monitor database capacity and cleanup progress.
Set request-rate and storage limits for the retained live-proof window; the
amortized sweep does not bound the number of proofs accepted within that window.
Malformed legacy markers with unknown expiry remain for investigation. Legacy
markers with very large keys can still make individual index operations costly;
measure and address them before enabling this code on an existing database.

Drizzle Kit 0.31 generated invalid SQL for the expiry expression by splitting
its internal commas; migration `0027` was corrected before deployment. When a
future migration changes or rebuilds `secret`, inspect the generated index SQL
and verify its expression and partial predicate before applying it. CI must
apply all migrations and run the replay cleanup and populated-upgrade tests,
including their index-plan assertions.

Resource DPoP admission checks the verified token and live session together with
its replay marker in one D1 transaction. That transaction is the authorization
decision boundary. A later private read or mutation that must not continue after
revocation needs an additional session fence in its own storage transaction.
