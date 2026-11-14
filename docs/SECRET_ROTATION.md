# Secret Rotation Procedures

Before changing a credential, verify the Cloudflare account, Worker and named
environment. Back up the relevant configuration and data, test the change in
staging, and plan for clients to reauthenticate. The local deployment preflight
cannot inspect remote secrets or prove that a rotation reached every Worker
instance.

## Session signing key

Current access and refresh JWTs use `SESSION_JWT_SECRET` when configured. When
it is absent, the Worker uses a `session_jwt_secret` generated and stored in D1.
The runtime creates the D1 value only if it does not already exist; it does not
overwrite an existing value when the environment secret changes.

Alteran now reads the key from the request's Worker Env, not Astro's global env
accessor. If the intended key was available only through Astro, configure the
matching Worker secret or Secret Store binding before rollout and review the D1
key independently. Falling back to a different D1 key changes which sessions can
be verified.

Changing the configured session key makes tokens signed with a different key
fail verification on instances using the new key. This can affect both access
and refresh tokens, including OAuth sessions; clients may need to sign in again.
During rollout, verify the actual deployed version and behavior rather than
assuming every instance changed at once.

After confirming the target account and Worker, an operator who has chosen to
use an environment secret can set the new value with:

```bash
deno run -A npm:wrangler secret put SESSION_JWT_SECRET --env production
```

Removing that secret can make the Worker fall back to an older key still in D1.
Do not treat removal as a revocation procedure. Key changes do not themselves
remove stored refresh-session records, and this repository does not provide a
verified bulk-revocation or D1 key-rotation runbook. Do not execute ad hoc SQL
against production without an independently reviewed procedure and backup.

Older-format JWTs are not accepted by the updated Worker. Affected clients must
authenticate again. Current non-OAuth refresh sessions still use the existing
refresh-table token kind and are not rejected on that basis.

During a deployment with mixed Worker versions, an older version may still
accept behavior that the updated version rejects. Drain or replace all older
versions before relying on the new behavior, and verify the active deployment
and any rollback target. Rolling back to an older version can restore the old
verification behavior.

## User password

Change `USER_PASSWORD` for the intended environment after verifying the account
and Worker:

```bash
deno run -A npm:wrangler secret put USER_PASSWORD --env production
```

The password change does not by itself guarantee that already-issued sessions
are revoked. Check the deployment and session behavior, and arrange any
necessary reauthentication separately.

## Repository signing key

The signing key is part of the account's protocol identity. Replacing
`REPO_SIGNING_KEY` without coordinating the DID document and repository state
can interrupt signing or verification. Preserve verified backups and use a
reviewed AT Protocol identity-rotation procedure; this repository does not
provide an automated key migration or rollback procedure.

## DID and handle

`PDS_DID`, `PDS_HANDLE` and `PDS_HOSTNAME` are configured as named environment
vars in this repository. Check for conflicting remote secrets before changing
them. DID changes affect federation and require a separately reviewed migration;
this guide does not prescribe direct database edits. For a handle change,
coordinate account identity, DNS and the relevant AT Protocol records.

## Incident response

If credentials may be compromised, restrict access, preserve evidence, and
review the applicable session, identity and signing-key procedures above. A
successful secret update is not proof that all sessions were revoked or that all
data is safe. Verify the deployed state and notify affected users as
appropriate.

## References

- [AT Protocol security](https://atproto.com/specs/security)
- [JWT best practices](https://datatracker.ietf.org/doc/html/rfc8725)
- [Cloudflare Workers secrets](https://developers.cloudflare.com/workers/configuration/secrets/)
