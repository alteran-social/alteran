# Secret Rotation Procedures

This document describes how to safely rotate secrets in your PDS deployment.

## Overview

Secret rotation is a critical security practice. This guide covers rotation procedures for all secrets used by the PDS.

## JWT Secrets Rotation

### Access Token Secret

**Impact**: All active access tokens will be invalidated. Users will need to refresh their tokens.

**Procedure**:

1. **Generate new secret**:
   ```bash
   openssl rand -base64 32
   ```

2. **Set new secret** (staging first):
   ```bash
   wrangler secret put REFRESH_TOKEN --env staging
   ```

3. **Test in staging**:
   - Verify existing sessions can refresh
   - Verify new logins work
   - Check error logs

4. **Deploy to production**:
   ```bash
   wrangler secret put REFRESH_TOKEN --env production
   ```

5. **Monitor**:
   - Watch for authentication errors
   - Users will need to refresh tokens (automatic on next request)

**Rollback**: Keep the old secret for 1 hour to allow in-flight requests to complete.

### Refresh Token Secret

**Impact**: All refresh tokens will be invalidated. Users will need to log in again.

**Procedure**:

1. **Announce maintenance window** (users will be logged out)

2. **Generate new secret**:
   ```bash
   openssl rand -base64 32
   ```

3. **Set new secret**:
   ```bash
   wrangler secret put REFRESH_TOKEN_SECRET --env production
   ```

4. **Clear token revocation table** (optional):
   ```sql
   DELETE FROM token_revocation WHERE exp < <current_timestamp>;
   ```

5. **Notify users** to log in again

**Rollback**: Not possible - users must re-authenticate.

## Repository Signing Key Rotation

**Impact**: Requires repository migration. This is a major operation.

**⚠️ Warning**: This invalidates all existing commits. Only rotate if the key is compromised.

**Procedure**:

1. **Generate new signing key**:
   ```bash
   # Generate a new secp256k1 key as needed via your preferred tooling
   ```

2. **Backup current repository**:
   ```bash
   # Export current repo
   curl "https://your-pds.example.com/xrpc/com.atproto.sync.getRepo?did=<your-did>" \
     -o backup-$(date +%Y%m%d).car
   ```
   For a complete service backup before rotation, follow
   [`BACKUP_RESTORE.md`](BACKUP_RESTORE.md); a CAR file does not include R2
   blobs, sessions, token revocation state, or private operational state.

3. **Set new signing key**:
   ```bash
   wrangler secret put REPO_SIGNING_KEY --env production
   ```

4. **Trigger repository re-signing**:
   - This requires a custom migration script
   - All commits must be re-signed with the new key
   - MST must be rebuilt

5. **Update DID document** (if using did:web):
   - Ensure your PLC operation or did:web document advertises `verificationMethods.atproto` as the did:key derived from the new REPO_SIGNING_KEY.
   - Publish to `/.well-known/did.json` if using did:web.

6. **Verify**:
   ```bash
   # Check latest commit signature
   curl "https://your-pds.example.com/xrpc/com.atproto.sync.getLatestCommit?did=<your-did>"
   ```

**Rollback**: Restore from backup and revert signing key.

## User Password Rotation

**Impact**: User must log in with new password.

**Procedure**:

1. **Set new password**:
   ```bash
   wrangler secret put USER_PASSWORD --env production
   ```

2. **User logs in** with new password

3. **Old sessions remain valid** until tokens expire

**Rollback**: Set old password back.

## DID and Handle Updates

### Changing DID

**⚠️ Warning**: Changing DID is not recommended. It breaks federation.

If you must change DID:

1. **Export repository**:
   ```bash
   curl "https://your-pds.example.com/xrpc/com.atproto.sync.getRepo?did=<old-did>" \
     -o migration-$(date +%Y%m%d).car
   ```

2. **Set new DID**:
   ```bash
   wrangler secret put PDS_DID --env production
   ```

3. **Update database**:
   ```sql
   UPDATE repo_root SET did = '<new-did>' WHERE did = '<old-did>';
   UPDATE record SET did = '<new-did>' WHERE did = '<old-did>';
   UPDATE blob_ref SET did = '<new-did>' WHERE did = '<old-did>';
   ```

4. **Update DID document** (if using did:web)

5. **Notify relays** of DID change

### Changing Handle

**Impact**: Users will need to update their handle references.

**Procedure**:

1. **Set new handle**:
   ```bash
   wrangler secret put PDS_HANDLE --env production
   ```

2. **Update DNS** (if using did:web):
   - Add TXT record: `_atproto.<new-handle>` → `did=<your-did>`

3. **Verify**:
   ```bash
   curl "https://your-pds.example.com/xrpc/com.atproto.identity.resolveHandle?handle=<new-handle>"
   ```

4. **Update profile** in client apps

**Rollback**: Set old handle back and revert DNS.

## Rotation Schedule

### Recommended Rotation Frequency

| Secret | Frequency | Priority |
|--------|-----------|----------|
| `REFRESH_TOKEN` | Every 90 days | Medium |
| `REFRESH_TOKEN_SECRET` | Every 180 days | Medium |
| `USER_PASSWORD` | As needed | High (if compromised) |
| `REPO_SIGNING_KEY` | Never (unless compromised) | Critical |
| `PDS_DID` | Never | Critical |
| `PDS_HANDLE` | As needed | Low |

### Automated Rotation

Consider implementing automated rotation for JWT secrets:

```typescript
// Example: Dual-secret validation during rotation
function validateToken(token: string, env: Env): boolean {
  try {
    // Try new secret first
    return verifyJWT(token, env.REFRESH_TOKEN);
  } catch {
    // Fall back to old secret (if in rotation window)
    if (env.REFRESH_TOKEN_OLD) {
      return verifyJWT(token, env.REFRESH_TOKEN_OLD);
    }
    throw new Error('Invalid token');
  }
}
```

## Emergency Rotation

If a secret is compromised:

1. **Immediately rotate** the compromised secret
2. **Revoke all tokens** (if JWT secret compromised):
   ```sql
   -- Mark all tokens as revoked
   INSERT INTO token_revocation (jti, exp, revoked_at)
   SELECT jti, exp, <current_timestamp>
   FROM active_tokens;
   ```
3. **Force re-authentication** for all users
4. **Audit logs** for suspicious activity
5. **Notify users** if data may have been accessed

If secret compromise coincides with data loss or service instability, switch to
the incident flow in [`DISASTER_RECOVERY.md`](DISASTER_RECOVERY.md) and restore
from a known-good backup before returning traffic.

## Checklist

Before rotating any secret:

- [ ] Backup current configuration
- [ ] Test rotation in staging environment
- [ ] Schedule maintenance window (if needed)
- [ ] Prepare rollback plan
- [ ] Notify users (if needed)
- [ ] Monitor logs during and after rotation
- [ ] Verify functionality after rotation
- [ ] Document the rotation in change log

## Troubleshooting

### Users Can't Authenticate After Rotation

**Cause**: Token validation failing with new secret.

**Solution**:
1. Check secret was set correctly: `wrangler secret list --env production`
2. Verify no typos in secret value
3. Check logs for specific error messages
4. Rollback if necessary

### Repository Commits Invalid After Signing Key Rotation

**Cause**: Commits signed with old key, verified with new key.

**Solution**:
1. Verify signing key is correct
2. Re-sign all commits with new key
3. Rebuild MST with new signatures
4. Update DID document

### DID Resolution Failing After Handle Change

**Cause**: DNS not updated or propagation delay.

**Solution**:
1. Verify DNS TXT record: `dig TXT _atproto.<handle>`
2. Wait for DNS propagation (up to 48 hours)
3. Use DID directly until DNS propagates

## References

- [AT Protocol Security](https://atproto.com/specs/security)
- [JWT Best Practices](https://datatracker.ietf.org/doc/html/rfc8725)
- [Cloudflare Workers Secrets](https://developers.cloudflare.com/workers/configuration/secrets/)
