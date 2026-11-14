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
- Space and policy XRPC namespaces return `NotImplemented`; `space:` OAuth
  scopes are not granted. An independently granted `transition:generic` scope
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

The `spaces-reference-interop.test.ts` and `spaces-reference-lexicon.test.ts`
tests can exercise a disposable local reference PDS. Set
`ALTERAN_REFERENCE_INTEROP_CONFIG` to a JSON file containing
`pds`, `plc`, `did`, and `accessJwt` for a test account. Both service URLs must
be loopback HTTP origins. The test creates a uniquely named space, exchanges a
STAR archive and verifies response MACs, then attempts to delete the test space.
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

Apply database migrations `0014` and `0015` in order before deploying code that
uses them. Public blob cleanup queries consult the new private-usage table, so
deploying the Worker first would break those cleanup operations.

For migrations `0016`–`0018`, stop any internal Space writers during the
upgrade. Existing Space repositories are preserved in quarantined epochs and
remain unavailable until a future verification and activation path is added.
Keep a recoverable database backup before applying migrations.
