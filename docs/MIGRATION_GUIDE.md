# Account Migration

Alteran does not currently provide a complete account migration flow. In
particular, it does not implement `com.atproto.repo.importRepo`, account
creation through `com.atproto.server.createAccount`, or importing AT Protocol
Spaces. Do not update an account's DID to point at Alteran on the assumption
that its repositories and blobs have been migrated.

## Accounts with Spaces

A public repository CAR from `com.atproto.sync.getRepo` contains the public
repository; it is not a backup of an account's Spaces. The Spaces migration
design also requires the account's space repositories and blobs, any metadata
for spaces it administers, and a new destination-host KEM key. Alteran cannot
import or serve this data yet. See [Spaces readiness](SPACES_READINESS.md).

Keep the account on its existing host and retain access to its data and
credentials until the destination and migration tools support all of the
account's data and the transfer has been verified. A DID document containing
`#atproto_kem` does not by itself establish whether an account has space data.

For a `did:plc` identity, applying a replacement `verificationMethods` map can
remove `atproto_kem`. Merely requesting recommended credentials changes
nothing, but signing and submitting such a replacement changes the identity.
Alteran's recommended-credentials endpoint refuses accounts with an existing
KEM key and cannot verify `did:web` identities; this does not prevent a manual
PLC update, a change made by another client, or a concurrent identity update.
Copying the old host's public KEM key is not a substitute for migrating: the
destination must hold its corresponding private key and serve the space data.

For `did:web`, changing the hosted DID document or the DNS/hosting behind it
can also replace the identity's keys and service endpoint. Keep the old
identity document and host available until a supported migration is ready.

## Backups

Follow the current host's instructions to export and verify the public
repository, its blobs, and any Spaces data separately. Keep control of the
account's DID and rotation credentials. A public CAR alone does not establish
that blob or Spaces backups are complete.

The [reference PDS migration guide](https://github.com/bluesky-social/pds/blob/main/ACCOUNT_MIGRATION.md)
describes its own software and should not be taken as evidence that Alteran
implements the same destination APIs.
