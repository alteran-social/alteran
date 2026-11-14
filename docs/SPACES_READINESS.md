# AT Protocol Spaces readiness

Alteran does not yet implement Spaces. The AT Protocol team's
[beta announcement](https://atproto.com/blog/getting-ready-for-the-spaces-public-beta)
schedules the public beta and reference-PDS rollout to start on December 1,
2026. Other PDS implementations must add their own support. The team advises
against using the alpha PDS for production data and warns that migrating from
alpha to beta will not be smooth.

Spaces provide access control, not end-to-end encryption: hosts and authorized
applications can read their contents. They must not be treated as public repo
records or advertised as encrypted.

## Current behavior

- Alteran has one public MST repository per account and serves its commits via
  public sync and the firehose. Internal space storage and protocol helpers are
  under development; no space repositories or space host are accessible yet.
- Space and policy XRPC namespaces return `NotImplemented`. OAuth can issue an
  explicitly requested `read_self` Space grant, but no public Space endpoint
  accepts it yet. The grant covers every collection in the user's own repo for
  matching Spaces, even when the request names a collection. Other Space grants
  remain unavailable. An independently granted `transition:generic` scope
  continues to authorize its existing public-repository operations.
- `com.atproto.sync.getBlob` authorizes public downloads using public record
  usage and sends public, immutable cache headers. The public blob usage path
  must never treat a space-only reference as public authorization.
- Account import and Spaces migration are not supported. The
  [migration guide](MIGRATION_GUIDE.md) describes the identity and backup limits.

## Implementation gates

The following is a design checklist, not a claim of beta compatibility. It
is based on [proposal 0016 at revision `b54ec68`](https://github.com/bluesky-social/proposals/blob/b54ec6853bab77edd4fd373804a480633094b324/0016-permissioned-data/README.md),
which explicitly remains a draft, and the reference implementation's
[Spaces branch at `16bfeba`](https://github.com/bluesky-social/atproto/tree/16bfeba760aede46f0b87bf94febef9e6ea84b95/packages/pds).
Recheck the released beta Lexicons, implementation, and migration guidance
before enabling any of these contracts.

1. **Storage and publication:** implement separate per-author, per-space
   repositories, commits, revision and operation history. Keep their records,
   blocks, exports, and notifications out of public repo reads, public CARs,
   debug routes, caches, and `subscribeRepos`. A space-only blob reference must
   not make the blob publicly readable or listable, including when the same
   CID also has a public reference that is subsequently deleted. Design D1
   batches and conflict handling for atomic writes and concurrent updates.
2. **Identity and credentials:** create and durably retain a distinct P-256
   KEM private key for the host before publishing its public key as
   `#atproto_kem`. Implement and verify the released key agreement, request
   signatures, credential binding, expiration, revocation, and replay rules.
   Never rotate or publish a key without a recoverable corresponding secret.
3. **Authorization and policy:** implement the released `space:` scope
   semantics and consent, bound delegation and space credentials, and the
   required personal, member, and managed policies. Cover every read, write,
   lifecycle, service-auth, and administrative operation; a public-repo grant
   must not imply space access.
4. **Sync and lifecycle:** implement the released Space XRPCs, writer
   discovery, notifications and retries, credential revocation, deletion,
   full and incremental sync, and the specified archive formats. Verify
   recovery after missed notifications and access changes.
5. **Migration and operations:** export and import all space repos, their
   blobs, and authority metadata before changing an account's identity; handle
   failed and partial transfers without losing the old copy. Test key rotation,
   backup and restore, deactivation, host migration, and resource limits on
   Workers, D1, and R2.

Before advertising support, run protocol conformance and interoperability tests
against the released reference PDS in both directions. Include unauthorized and
revoked readers, cross-space access, simultaneous writes, public/private
same-CID blobs, firehose and cache leakage, migration and recovery, and
regressions for ordinary public-repo clients. A local build or test suite alone
does not establish deployed or cross-implementation compatibility.

Space and public records both use `com.atproto.repo.uploadBlob`, so upload-time
intent does not identify which data will be private. A Spaces-capable upload
path must stage bytes in a private bucket without a public domain, verify the
raw CID against the stored bytes, and reserve quota for in-flight and orphaned
uploads. Public and Space associations must be checked separately; access to one
Space must not reveal a blob referenced only by another. Imports also need to
retain missing-blob associations until their bytes are uploaded.

## Development and deployment

The `spaces-reference-interop.test.ts`, `spaces-reference-lexicon.test.ts`,
`spaces-reference-policy.test.ts`, `spaces-reference-ops.test.ts`,
`spaces-reference-export.test.ts` and `spaces-reference-meta-archive.test.ts`
tests can exercise a disposable local reference PDS. Set
`ALTERAN_REFERENCE_INTEROP_CONFIG` to a JSON file containing
`pds`, `plc`, `did`, and `accessJwt` for a test account. Both service URLs must
be loopback HTTP origins. The archive and policy tests create uniquely named
spaces and then attempt to delete them. The archive test also exchanges a STAR
archive and verifies response MACs. The operation-log comparison runs the same
writes against local D1 and the reference PDS, then compares paginated
operations and the final digest.
The export test uploads an archive produced by the internal snapshot exporter
and verifies the imported record and digest; it buffers that small archive
before uploading and does not test streaming HTTP transport.
The metadata test imports and exports a memberspace policy, member, and writer.
An interrupted request may leave test data behind. Keep the configuration file
private because it contains an access token. The Lexicon test injects DNS and
maps test HTTPS origins to the local services; it does not establish live DNS or
deployed Cloudflare networking behavior.

The experimental Lexicon resolver depends on Cloudflare global `fetch` with
`global_fetch_strictly_public` enabled and the platform's public-egress
restrictions. The resolver is not exposed or used for OAuth grants. Before
enabling it, verify the flag in the deployed environment, test same-zone routing
and egress there, and establish a freshness policy for DID documents and repo
heads. Matching head responses cannot rule out consistent stale responses from
the publisher's PDS or a cache.

The experimental request-wide scope resolver permits at most two distinct
declaration-backed Space types per request, resolved serially under one
deadline. This deliberately limits interoperability until aggregate Worker
CPU, memory and concurrent DNS work can be bounded and measured. It is not
connected to OAuth; authenticated PAR and session binding, declaration
freshness and consent rechecks are required before it can grant scopes.

Drain older Workers when deploying the OAuth approval changes: older versions
can issue a code without the new atomic PAR consumption. Approvals rendered by
an older version must be restarted after the cutover.

The internal incremental-repo reader requires a known starting revision and
returns a full-sync result when history is uncertain. Its operation log is
currently immutable and unpruned; imports, pruning, and epoch replacement need
an atomic history fence before this reader can be exposed. Callers must still
authorize the request, authenticate the commit, and compare the final digest.

The internal snapshot exporter pages through a leased version history,
recomputes the snapshot digest, and emits the STAR terminator only after the
digest matches. It does not authorize an export or authenticate its commit.
Snapshot leases and version cleanup are bounded, but cleanup must run
regularly: response loss or Worker termination can leave a lease until expiry.
The indexed page reader relies on the database's non-overlapping version
interval invariant. Quarantined legacy epochs cannot be read through this path.
Validate the complete lease, cleanup, and concurrent-write workload on the
target D1 deployment before exposing an export route.

Record decoding is limited to 131,072 CBOR items and 100 levels per record.
The internal mutation path validates the CIDs of touched records and limits
their combined existing bytes to 4 MiB per batch, so some otherwise valid
large update or delete batches must be split. It relies on fenced D1 writers
and previously verified state for untouched records. The record JSON helper
cannot losslessly serialize integers outside JavaScript's safe range. Before
exposure, measure worst-case concurrent decoding, D1 response expansion and
serialization against the target Worker's CPU and memory limits.

The internal metadata archive codec is limited to 16 MiB and normalizes the
reference PDS's supported policy and member fields; it is not a lossless backup
or an authorized import. To avoid an ambiguous reference member-key mapping,
it rejects member DIDs with multiple method-specific segments, including some
valid `did:web` identities. Migration cannot rely on this codec until that
identity mapping and preservation of all required state are resolved.

An internal personal-Space lifecycle can tombstone a newly created personal
Space and page through its local D1 records and history. It fences old leases
and writers and permanently rejects recreation. It only applies when there are
no external credentials, registered syncers, blob references or quarantine
receipts. It does not send deletion notifications, clean R2, or securely erase
copies and database backups. Exposing deletion requires those contracts and a
recovery path for unfinished cleanup. Incremental sync must also handle its
history boundary; pruning the operation log for live Spaces remains unsupported.

Apply database migrations `0014` and `0015` in order before deploying code that
uses them. Public blob cleanup queries consult the new private-usage table, so
deploying the Worker first would break those cleanup operations.

For migrations `0016`–`0018`, stop any internal Space writers during the
upgrade. Existing Space repositories are preserved in quarantined epochs. An
internal verifier exists, but activation remains disabled by migration `0017`;
verification of local consistency alone does not authenticate an external
commit. The one-statement legacy backfill, recovery procedure, and activation
need production-scale validation before any quarantined data is made available.
Keep a recoverable database backup before applying migrations.

Migrations `0019` and `0020` add database fences for current Space writes and
snapshot pruning. Deploy them in order with old Space writers quiesced. Older
writers must not be restarted against the upgraded database. The trigger and
batch behavior still requires validation on the target D1 deployment before
these internal storage paths are enabled. Space operation-log pruning is not
yet available.

Migrations `0021`–`0031` add quarantine checkpoints, replay tracking, snapshot
lease safeguards, cleanup indexes, and confidential-client key-binding state.
Apply them in order with old Workers drained; older code does not enforce all
the new fences. Follow [the OAuth replay and cutover notes](OAUTH_REPLAY_CLOCK.md)
before deployment, including the separate backup-restore procedure and any
required confidential-client reauthorization. Production cleanup scheduling,
backlog monitoring, and D1 load testing remain deployment gates.

Migrations `0032`–`0039` add the restricted lifecycle, immutable OAuth Space
grant snapshots, cleanup indexes, account incarnations and login reservation
nonces. Drain older Workers
before applying them, apply them in order, and do not restart old versions.
Apply `0038` atomically or recover from a backup if a manual application is
interrupted. The backfill, trigger behavior and indexed cleanup still require
validation on the target D1 deployment before enabling Space access.

The login and consent lockout uses the Cloudflare-provided `CF-Connecting-IP`
header; absent or invalid values share an `unknown` bucket. This assumes the
header comes from a trusted edge. A successful app-password login can clear
earlier primary-password failures for the same IP. Per-IP counters therefore
need account-wide or edge throttling and storage monitoring for distributed
guessing; they do not provide those controls themselves.
