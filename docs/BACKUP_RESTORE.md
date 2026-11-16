# Backup and Restore Runbook

This runbook describes how to back up and restore an Alteran single-user PDS.
It is operator-facing and assumes a Cloudflare Workers deployment with D1,
R2, and Wrangler configured for the target environment.

## Scope

Backups must cover four separate data sets:

- D1 database state: records, repo roots, commit log, tokens, preferences,
  blob indexes, and account state.
- R2 blob objects: media bytes referenced by records.
- Repository CAR export: a portable public-repo checkpoint from
  `com.atproto.sync.getRepo`.
- Runtime configuration: Wrangler environment, deployment revision, DNS, and
  secret names or encrypted secret escrow.

The repository CAR is not a complete service backup by itself. The AT Protocol
repository specs describe repository exports as CAR v1 files from
`com.atproto.sync.getRepo`; blob bytes are separate and must be restored by
CID. D1 remains the canonical Alteran restore source because it includes
private and operational state that a public repo CAR does not contain.

## Backup Schedule

Use a schedule that matches your acceptable data-loss window:

- D1 export: at least daily, and before every risky migration or secret
  rotation.
- R2 mirror: at least daily; increase to hourly if media uploads are frequent.
- Repository CAR export: daily, plus before identity, signing-key, or import
  operations.
- Configuration inventory: after every deploy or secret/config change.

Keep at least 30 daily restore points, 12 weekly restore points, and 12 monthly
restore points unless your compliance requirements demand a different policy.

## Backup Procedure

Create a timestamped backup directory:

```bash
export ENVIRONMENT=production
export PDS_HOST=your-pds.example.com
export PDS_DID=did:web:example.com
export BACKUP_TS="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "backups/${BACKUP_TS}"
```

Record the source revision and public identity:

```bash
git rev-parse HEAD > "backups/${BACKUP_TS}/git-revision.txt"
curl -fsS "https://${PDS_HOST}/.well-known/atproto-did" \
  > "backups/${BACKUP_TS}/atproto-did.txt"
curl -fsS "https://${PDS_HOST}/.well-known/did.json" \
  > "backups/${BACKUP_TS}/did.json"
```

Export D1:

```bash
bunx wrangler d1 export alteran-production \
  --env "${ENVIRONMENT}" \
  --remote \
  --output "backups/${BACKUP_TS}/d1.sql"
```

Export the public repository CAR:

```bash
curl -fsS \
  -H "Accept: application/vnd.ipld.car" \
  "https://${PDS_HOST}/xrpc/com.atproto.sync.getRepo?did=${PDS_DID}" \
  -o "backups/${BACKUP_TS}/repo.car"
```

Record the current repo head:

```bash
curl -fsS \
  "https://${PDS_HOST}/xrpc/com.atproto.sync.getHead?did=${PDS_DID}" \
  > "backups/${BACKUP_TS}/repo-head.json"
```

Mirror R2 through the S3-compatible API. Use the tool already approved for your
operations environment; for example:

```bash
aws s3 sync \
  "s3://alteran-blobs-production" \
  "backups/${BACKUP_TS}/r2/alteran-blobs-production" \
  --endpoint-url "${R2_ENDPOINT_URL}"
```

Record secret names and configuration without writing plaintext secrets into
the repository:

```bash
bunx wrangler secret list --env "${ENVIRONMENT}" \
  > "backups/${BACKUP_TS}/secret-names.txt"
cp wrangler.jsonc "backups/${BACKUP_TS}/wrangler.jsonc"
```

If you maintain an emergency secret escrow, export secret values only to an
encrypted vault managed outside Git. The restore must include `USER_PASSWORD`,
JWT secrets, `REPO_SIGNING_KEY`, DID/handle secrets, and any OAuth/client
configuration used in production.

Generate checksums after all backup files are present:

```bash
(cd "backups/${BACKUP_TS}" && find . -type f -print0 | sort -z | xargs -0 shasum -a 256) \
  > "backups/${BACKUP_TS}/SHA256SUMS"
```

## Restore Procedure

Start with the least destructive restore that fixes the incident. If the
current deployment is still serving traffic, stop writes first by routing
clients away from the Worker, disabling the public route, or applying a
maintenance rule at the edge.

1. Restore the code and configuration.

   ```bash
   git checkout "$(cat backups/${BACKUP_TS}/git-revision.txt)"
   bun install
   bun run build
   bunx wrangler deploy --env production
   ```

2. Restore secrets from your encrypted secret manager.

   ```bash
   bunx wrangler secret put USER_PASSWORD --env production
   bunx wrangler secret put REFRESH_TOKEN --env production
   bunx wrangler secret put REFRESH_TOKEN_SECRET --env production
   bunx wrangler secret put REPO_SIGNING_KEY --env production
   ```

3. Restore D1 from the SQL export.

   ```bash
   bunx wrangler d1 execute alteran-production \
     --env production \
     --remote \
     --file "backups/${BACKUP_TS}/d1.sql"
   ```

4. Restore R2 blobs through the S3-compatible API.

   ```bash
   aws s3 sync \
     "backups/${BACKUP_TS}/r2/alteran-blobs-production" \
     "s3://alteran-blobs-production" \
     --endpoint-url "${R2_ENDPOINT_URL}"
   ```

5. If the D1 export is unavailable or unusable, use the repository CAR as a
   fallback for public repo content after the PDS is redeployed and
   authenticated:

   ```bash
   curl -X POST "https://${PDS_HOST}/xrpc/com.atproto.repo.importRepo" \
     -H "Authorization: Bearer ${ACCESS_JWT}" \
     -H "Content-Type: application/vnd.ipld.car" \
     --data-binary "@backups/${BACKUP_TS}/repo.car"
   ```

   Then restore blobs and loop until the missing-blob list is empty:

   ```bash
   curl -fsS \
     -H "Authorization: Bearer ${ACCESS_JWT}" \
     "https://${PDS_HOST}/xrpc/com.atproto.repo.listMissingBlobs?limit=500"
   ```

   A CAR fallback does not restore active sessions, private preferences not
   present in D1, token revocation state, or operational metrics.

## Verification

Run these checks before returning the service to normal traffic:

```bash
curl -fsS "https://${PDS_HOST}/health"
curl -fsS "https://${PDS_HOST}/ready"
curl -fsS "https://${PDS_HOST}/.well-known/atproto-did"
curl -fsS "https://${PDS_HOST}/xrpc/com.atproto.server.describeServer"
curl -fsS "https://${PDS_HOST}/xrpc/com.atproto.sync.getHead?did=${PDS_DID}"
curl -fsS "https://${PDS_HOST}/xrpc/com.atproto.sync.getRepo?did=${PDS_DID}" \
  -o "/tmp/restore-check.car"
```

Also verify:

- `repo-head.json` from the backup matches the restored `getHead` response
  when restoring from the D1 backup.
- `listMissingBlobs` is empty or contains only intentionally unavailable blobs.
- New login, `getSession`, record create, record delete, and blob upload work
  with the restored service.
- Relay crawl notification succeeds if relay publishing is enabled.

## Restore Drills

Run a restore drill at least quarterly:

1. Restore the latest backup into a staging environment.
2. Verify `/health`, `/ready`, DID routes, repository export, and missing
   blobs.
3. Record the restore time, missing manual steps, and any failed commands.
4. Update this runbook before relying on the next backup.

## Security

- Encrypt backups at rest.
- Keep backup storage in a different failure domain from the production Worker,
  D1 database, and R2 bucket.
- Restrict backup write/delete access to automation identities.
- Test restore access separately from backup-write access.
- Never commit backup artifacts, SQL dumps, CAR files, R2 mirrors, or plaintext
  secrets to the repository.
