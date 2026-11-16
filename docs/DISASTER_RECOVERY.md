# Disaster Recovery Runbook

This runbook describes how to recover an Alteran single-user PDS from a
production incident. Use it with the backup procedure in
[`BACKUP_RESTORE.md`](BACKUP_RESTORE.md).

## Recovery Objectives

Set these values before an incident:

- RPO: maximum acceptable data loss. This should match the D1/R2 backup
  interval.
- RTO: maximum acceptable outage length. This should be proven by restore
  drills, not estimated during an incident.
- Recovery owner: the person allowed to rotate secrets, restore D1, and change
  DNS or Cloudflare routes.

## Failure Modes

| Failure | Symptoms | Primary recovery path |
| --- | --- | --- |
| Bad Worker deploy | `/health` or XRPC routes fail after deploy | Roll back Worker version, then redeploy last known-good revision |
| D1 corruption or loss | `/health` database check fails, records disappear, repo head invalid | Restore D1 SQL backup, then verify repo head and sessions |
| R2 blob loss | records exist but media fetches fail or `listMissingBlobs` grows | Restore R2 mirror, then verify blob CIDs |
| Secret compromise | unexpected auth, signing, or session behavior | Rotate affected secrets and revoke sessions as needed |
| Signing-key compromise | commit signatures cannot be trusted | Freeze writes, restore pre-compromise backup, rotate identity/signing material only with a migration plan |
| DNS or identity failure | DID/handle resolution breaks | Restore DNS, `did.json`, and configured DID/handle values before replaying data |
| Full Cloudflare project loss | Worker, D1, R2, or bindings unavailable | Recreate resources, restore config/secrets, restore D1/R2, then verify identity |

## Incident Procedure

### 1. Stabilize

1. Declare the incident and assign one recovery owner.
2. Freeze writes if data integrity is uncertain.
3. Capture current evidence before making destructive changes:

   ```bash
   curl -i "https://${PDS_HOST}/health"
   curl -i "https://${PDS_HOST}/ready"
   curl -i "https://${PDS_HOST}/xrpc/com.atproto.sync.getHead?did=${PDS_DID}"
   bunx wrangler d1 info alteran-production --env production
   ```

4. If a secret is compromised, rotate only the compromised secret first. Do not
   rotate `REPO_SIGNING_KEY` during a live incident unless the signing key is
   the confirmed compromise.

### 2. Choose a Restore Point

Pick the newest backup whose D1 export, R2 mirror, repo CAR, checksums, and
configuration inventory are all present. Verify the backup manifest:

```bash
(cd "backups/${BACKUP_TS}" && shasum -a 256 -c SHA256SUMS)
```

If the newest restore point is incomplete, move backward until the backup set
is complete.

### 3. Restore in Dependency Order

Recover in this order:

1. DNS and identity host routes.
2. Worker code and Wrangler bindings.
3. Secrets.
4. D1 database.
5. R2 blobs.
6. Repository CAR fallback only if the D1 restore cannot be used.
7. Relay crawl notification and downstream verification.

The order matters: restoring repo content before identity, config, or secrets
are correct can create misleading smoke-test results.

### 4. Verify Service Health

Run the smoke tests from [`BACKUP_RESTORE.md`](BACKUP_RESTORE.md#verification),
then perform authenticated checks:

```bash
curl -X POST "https://${PDS_HOST}/xrpc/com.atproto.server.createSession" \
  -H "Content-Type: application/json" \
  -d "{\"identifier\":\"${PDS_HANDLE}\",\"password\":\"${USER_PASSWORD}\"}"

curl -fsS \
  -H "Authorization: Bearer ${ACCESS_JWT}" \
  "https://${PDS_HOST}/xrpc/com.atproto.server.getSession"
```

Verify that:

- `/health` and `/ready` are 200.
- `/.well-known/atproto-did` returns the configured DID.
- `/.well-known/did.json` advertises the expected service endpoint and signing
  key.
- `getHead` matches the selected restore point when restoring from D1.
- `getRepo` returns a CAR file with content.
- `listMissingBlobs` is empty or only contains accepted missing media.
- A test record write and delete produces a new repo head.

### 5. Return Traffic

Only return normal traffic after verification passes. If the deployment was
blocked by an edge rule, remove the rule after the final smoke test. If relays
need to re-crawl the PDS, trigger the relay notification script or run the
documented manual crawl request.

## Rollback Criteria

Abort the restore and roll back to the previous known-good state if any of
these occur:

- The D1 import fails or creates an inconsistent repo head.
- The restored Worker cannot read required secrets.
- DID or handle resolution points at a different service than the restored PDS.
- Blob restore causes missing media to increase.
- Authenticated writes fail after sessions are recreated.

When rollback is needed, keep the failed restore environment isolated for
analysis. Do not overwrite the backup set that was used for the failed restore.

## Communication

For a single-user deployment, the operator may be the only user, but the same
record keeping still matters. Record:

- incident start and end time;
- affected routes and data sets;
- chosen restore point and backup timestamp;
- commands run;
- secrets rotated;
- data loss, if any;
- follow-up issues.

## Closeout

After recovery:

1. Export a fresh D1 backup and repo CAR from the restored system.
2. Confirm the new backup can be checksummed and stored.
3. File issues for any manual step that slowed recovery.
4. Update [`BACKUP_RESTORE.md`](BACKUP_RESTORE.md), this runbook, and
   [`SECRET_ROTATION.md`](SECRET_ROTATION.md) if the incident changed the
   recovery procedure.
