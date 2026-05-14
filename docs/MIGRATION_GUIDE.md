# Account Migration Guide

This guide explains how to migrate an existing AT Protocol account to your Alteran single-user PDS while preserving your identity and content.

## Overview

Alteran supports two migration paths:

- **Path A**: Start fresh with a new `did:web` identity (no migration needed)
- **Path B**: Preserve your existing identity and migrate all content from another PDS

This guide focuses on **Path B** - migrating your existing account.

## Prerequisites

- Your Alteran PDS is deployed and running
- You have admin access to your current PDS (or backups of your data)
- You control DNS for your domain
- You have configured all required secrets (see [Configuration](#configuration))
- You have reviewed the [backup and restore runbook](BACKUP_RESTORE.md) if
  migrating from a local backup rather than a live old PDS

## Terminology

- **Old PDS**: Where your account currently lives (e.g., bsky.social)
- **New PDS**: Your Alteran deployment
- **did:web**: DID anchored to your domain via `/.well-known/did.json`
- **did:plc**: DID anchored in the PLC directory

## Configuration

Before starting migration, ensure these environment variables are set:

### Required Secrets
- `PDS_DID` - Your DID (did:web or did:plc)
- `PDS_HANDLE` - Your handle (e.g., username.domain.com)
- `PDS_HOSTNAME` - Your PDS hostname
- `USER_PASSWORD` - Password for authentication
- `REFRESH_TOKEN` - JWT access token secret
- `REFRESH_TOKEN_SECRET` - JWT refresh token secret
- `REPO_SIGNING_KEY` - secp256k1 signing key (hex or base64 32 bytes)

### Verify Deployment

Check that your PDS is ready:

```bash
# Health check
curl https://your-domain.com/health

# Verify DID
curl https://your-domain.com/.well-known/atproto-did

# Check DID document
curl https://your-domain.com/.well-known/did.json
```

## Migration Steps

### 1. Authenticate with New PDS

Get an access token:

```bash
curl -X POST https://your-domain.com/xrpc/com.atproto.server.createSession \
  -H "Content-Type: application/json" \
  -d '{
    "identifier": "your-handle",
    "password": "your-password"
  }'
```

Save the `accessJwt` from the response for subsequent requests.

### 2. Create Deactivated Account

Create your account in deactivated state:

```bash
curl -X POST https://your-domain.com/xrpc/com.atproto.server.createAccount \
  -H "Authorization: Bearer YOUR_ACCESS_JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "did": "your-did",
    "handle": "your-handle",
    "deactivated": true
  }'
```

### 3. Export Repository from Old PDS

Download your repository as a CAR file:

```bash
curl -o repo.car \
  "https://old-pds.com/xrpc/com.atproto.sync.getRepo?did=YOUR_DID"
```

### 4. Import Repository to New PDS

Upload the CAR file:

```bash
curl -X POST https://your-domain.com/xrpc/com.atproto.repo.importRepo \
  -H "Authorization: Bearer YOUR_ACCESS_JWT" \
  -H "Content-Type: application/vnd.ipld.car" \
  --data-binary @repo.car
```

### 5. Check Migration Status

Verify the import:

```bash
curl -H "Authorization: Bearer YOUR_ACCESS_JWT" \
  https://your-domain.com/xrpc/com.atproto.server.checkAccountStatus
```

This shows:
- Record count
- Blob count
- Repository head
- Activation status

### 6. Migrate Blobs

List missing blobs:

```bash
curl -H "Authorization: Bearer YOUR_ACCESS_JWT" \
  "https://your-domain.com/xrpc/com.atproto.repo.listMissingBlobs?limit=500"
```

For each missing blob:

```bash
# Download from old PDS
curl -o blob.bin \
  "https://old-pds.com/xrpc/com.atproto.sync.getBlob?did=YOUR_DID&cid=BLOB_CID"

# Upload to new PDS
curl -X POST https://your-domain.com/xrpc/com.atproto.repo.uploadBlob \
  -H "Authorization: Bearer YOUR_ACCESS_JWT" \
  -H "Content-Type: application/octet-stream" \
  --data-binary @blob.bin
```

Repeat until all blobs are transferred.

### 7. Update Identity

#### For did:web

Your new PDS already serves the correct DID document. Update DNS if needed to point to your new PDS.

#### For did:plc

1. Get recommended credentials from new PDS:

```bash
curl -H "Authorization: Bearer YOUR_ACCESS_JWT" \
  https://your-domain.com/xrpc/com.atproto.identity.getRecommendedDidCredentials
```

2. Update PLC directory (requires access to old PDS or rotation keys)

### 8. Activate Account

Once everything is migrated and verified:

```bash
curl -X POST https://your-domain.com/xrpc/com.atproto.server.activateAccount \
  -H "Authorization: Bearer YOUR_ACCESS_JWT"
```

### 9. Deactivate Old PDS

If you have access to the old PDS:

```bash
curl -X POST https://old-pds.com/xrpc/com.atproto.server.deactivateAccount \
  -H "Authorization: Bearer OLD_PDS_ACCESS_JWT"
```

### 10. Update Clients

Log out and log back in on all your AT Protocol clients (apps, browsers) to use the new PDS.

## Troubleshooting

### Migration Fails

- Check account status to see what was imported
- Verify all blobs were transferred
- Check logs for errors
- Keep old PDS active until migration succeeds

### Missing Blobs

- Re-run `listMissingBlobs` to get updated list
- Verify blob CIDs match between old and new PDS
- Check blob storage quota

### Identity Update Issues

- Verify DID document is accessible
- For did:plc, ensure you have rotation keys
- Check DNS propagation for did:web

## Rollback

If migration fails:

1. Keep old PDS active
2. Fix issues on new PDS
3. Re-run migration steps
4. Don't activate new PDS until fully verified

If the old PDS is unavailable and you are restoring from local backups, follow
[`BACKUP_RESTORE.md`](BACKUP_RESTORE.md) first, then return to the migration
verification steps above.

## Security Notes

- All migration endpoints require authentication
- Only the configured `PDS_DID` can be migrated
- Deactivated accounts cannot make changes
- Rate limits apply to all operations

## Support

For issues or questions:
- Check implementation details in [`MIGRATION_IMPLEMENTATION.md`](MIGRATION_IMPLEMENTATION.md)
- Review endpoint documentation in [`API.md`](API.md)
- File issues on the project repository
