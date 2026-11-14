# AT Protocol Spaces readiness

Alteran has limited Space foundations and restricted owner-only reads; it is not
yet a Spaces-capable PDS. The AT Protocol team's
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
  public sync and the firehose. Space records and their history are stored
  separately and are not published through those public paths.
- `com.atproto.space.getRecord` supports an unsigned, DPoP-authenticated read
  of the user's own repository for an explicitly granted `read_self` Space
  scope. The scope covers every collection in matching Spaces whether or not
  the request names a collection. Requests for a record MAC are rejected.
  Space creation, writes, policy operations, credentials and synchronization
  are not exposed; other Space grants remain unavailable. An independently
  granted `transition:generic` scope continues to authorize its existing
  public-repository operations.
- `com.atproto.space.listRecords` supports the same owner and grant checks for
  metadata-only pages when `excludeValues=true`. Pages contain at most 50
  records and are ordered by full record URI, descending. Cursors must belong
  to the requested Space and repository, and every page is reauthorized; pages
  are not a single snapshot. The reader compares at most 4 MiB of stored values
  within D1 and asks clients to reduce the limit when the page exceeds that
  bound. It checks current-version consistency but does not rehash values to
  verify their CIDs. Listing record values, pages of up to the reference
  maximum of 1,000, cross-prefix cursors and credential access remain unsupported.
  A Space without an active local epoch is denied rather than listed as empty.
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
`spaces-reference-export.test.ts`, `spaces-reference-meta-archive.test.ts` and
`spaces-reference-meta-members.test.ts` and `spaces-list-reference.test.ts`
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
The member-mapping test checks a paginated reference member list against a
separately exported metadata archive.
The list test compares metadata, CIDs, cursor paths and filtered pagination
against the reference PDS for matching test records.
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

The internal local KEM identity resolver checks the configured key and PDS
origin against a bounded DID-document response, then rereads the configuration.
It supports `did:plc` and hostname-only `did:web`; it is not wired to HTTP and
does not prove current PLC state, DNS-to-connect safety or continued key
freshness. It has the same public-egress prerequisites as the Lexicon resolver.
Before using it for signed responses, establish authoritative identity freshness,
rotation handling and binding to the authenticated account incarnation.

On Linux, `scripts/space-kem-key.ts` can create a new local P-256 KEM key in
an owner-only directory outside any Git worktree. The destination must not
already exist. The script writes and verifies an owner-only private file, syncs
the file and directory, and prints only its public `did:key`. It takes an
advisory lock; ensure no other process can write the file while it runs. The
printed key reflects the last verification and can become stale if the file
changes afterward. For example:

```sh
deno run --allow-read --allow-write --allow-sys=uid scripts/space-kem-key.ts create /secure/alteran/space-kem.key
```

If output is lost, run the same command with `public` in place of `create` to
verify the existing file and recover its public key. A failed or interrupted
creation may leave a partial file: inspect it rather than overwriting it. Use a
trusted local filesystem, directory and ancestor paths; filesystem sync is not
a guarantee against storage failure. Back up the private key independently and
install it securely as `PDS_SPACE_KEM_KEY` before considering any DID update.
The tool does not install a secret, verify an existing PLC key, publish a DID
update or perform account migration. Do not replace an already published KEM
key without a verified migration and rotation procedure.

Space XRPC query strings contain private identifiers. The supplied Wrangler
configuration disables automatic invocation logs and traces while retaining
application logs; verify those settings in every deployed environment. OAuth
and Space protocol failures are sanitized at the Worker and middleware
boundaries. For ambiguous encoded paths, middleware conservatively applies
private, no-store handling; an OAuth JWKS served under a non-root base also
uses no-store. Sanitized server errors discard their original body and headers.
Audit Astro debug hooks, tail consumers, Logpush, other export destinations, proxies
and edge logs separately before enabling private reads. Local middleware tests
cannot establish what those systems record.

The experimental request-wide scope resolver permits at most two distinct
declaration-backed Space types per request, resolved serially under one
deadline. This deliberately limits interoperability until aggregate Worker
CPU, memory and concurrent DNS work can be bounded and measured. It is not
connected to OAuth; authenticated PAR and session binding, declaration
freshness and consent rechecks are required before it can grant scopes.

Drain older Workers when deploying the OAuth approval changes: older versions
can issue a code without the new atomic PAR consumption. Approvals rendered by
an older version must be restarted after the cutover. Workers must also be
drained before issuing collection-free `read_self` grants: older code cannot
restore their consent snapshots.

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
or an authorized import. The strict reader rejects ambiguous reference member
keys. A separate reader can match such keys and access bits against a complete,
independently authenticated membership snapshot, and returns semantic DIDs;
its writer accepts only DIDs that round-trip through the reference mapping.
These checks establish correspondence to the supplied snapshot, not its
authenticity or freshness. Migration must bind the complete, paginated snapshot
to the same quiesced or pinned Space and authority/account incarnation, and
authenticate the policy, writer state and archive separately.

An internal personal-Space lifecycle can tombstone a newly created personal
Space and page through its local D1 records and history. It fences old leases
and writers and permanently rejects recreation. It only applies when there are
no external credentials, registered syncers, blob references or quarantine
receipts. It does not send deletion notifications, clean R2, or securely erase
copies and database backups. Exposing deletion requires those contracts and a
recovery path for unfinished cleanup. Incremental sync must also handle its
history boundary; pruning the operation log for live Spaces remains unsupported.

The internal private-blob ledger is not connected to an upload or download
route. Its caller must authenticate the owner, retain the server-created
reservation handle across retries, and supply a dedicated R2 bucket with no
public access; the binding does not reveal the bucket's identity to the
helper. Apply migrations `0040` and `0041` before running this code and keep
older Workers drained during the upgrade. Reservations are tied to an account
incarnation, limited to 64 per DID across incarnations and 256 globally, and
each permanently reserves 5 MiB, even for failed or empty uploads. They are
separate from the public blob quota. There is no release or cleanup path: normal
use eventually exhausts these slots, and a timed-out PUT may still complete
after a negative read. A staged status is a historical receipt, not a check
that the object is still present. The ledger assumes the installed D1 trigger
set and R2 binding are trusted; an unexpected trigger can consume permanent
capacity within the caps. Validate create-only PUT and checksum/version
metadata on the target R2 service before relying on this foundation. Public
promotion, Space associations, snapshot retention, missing-blob import,
deletion and safe recovery remain unimplemented.

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

Migrations `0042` and `0043` bind Space epochs and personal policy state to an
account incarnation. Drain older Workers before applying either migration,
apply them in order, and do not restart old versions. Existing NULL ownership
remains quarantined; it is not automatically assigned to a recreated account.
Space identities and tombstones are retained until a separately fenced recovery
and retention procedure is available. Verify the migration and restore process
on the target D1 deployment before enabling Space reads.

The login and consent lockout uses the Cloudflare-provided `CF-Connecting-IP`
header; absent or invalid values share an `unknown` bucket. This assumes the
header comes from a trusted edge. A successful app-password login can clear
earlier primary-password failures for the same IP. Per-IP counters therefore
need account-wide or edge throttling and storage monitoring for distributed
guessing; they do not provide those controls themselves.
