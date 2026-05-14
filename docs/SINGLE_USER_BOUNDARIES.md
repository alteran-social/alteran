# Single-User Boundaries

Alteran is a single-user AT Protocol PDS. It is not a public multi-user PDS,
an account-hosting platform, a moderation service, or an Ozone-style admin
system. This document marks the production-readiness boundaries that follow
from that product target.

## Deliberate Non-Goals

These capabilities are intentionally out of scope unless Alteran's product
target changes:

- public account signup;
- invite-code creation, listing, and queue management;
- signup queues and phone verification flows;
- hosted account-recovery queues for arbitrary users;
- in-product terms-of-service acceptance during public signup;
- moderation administration, public report triage, or running a labeler/Ozone
  service.

This does not mean every possible related AT Protocol method returns the same
runtime response. Stable 501 responses are guaranteed only for the explicit
single-user unsupported XRPC routes documented in [`API.md`](API.md). Other
routes may require authentication first, may be proxied to configured external
services, or may return the generic unsupported response path.

## Operator Responsibilities

Because there is only one hosted account, production readiness depends on
operator controls rather than public account-management workflows.

### Terms and Privacy

Configure public policy links when the deployment is visible to other clients:

- `PDS_LINK_TOS`
- `PDS_LINK_PRIVACY`

`com.atproto.server.describeServer` advertises these links when configured.
Alteran does not run a public signup or ToS-acceptance workflow. If the operator
needs a formal acceptance process, it must live outside Alteran or be added as
a separate product feature.

### Account Recovery

Single-user recovery is operational recovery. The operator must retain:

- DID control, including `did:web` hosting or PLC rotation authority;
- DNS and handle control;
- encrypted access to `USER_PASSWORD`, JWT secrets, and `REPO_SIGNING_KEY`;
- D1, R2, and repository CAR backups;
- the deployment revision and Wrangler configuration needed to restore the
  Worker.

Use the operator's backup and disaster-recovery procedures, plus
[`SECRET_ROTATION.md`](SECRET_ROTATION.md) when credential rotation is needed.
Alteran does not expose a hosted password-reset or account-recovery queue for
third-party users.

### Moderation and Reports

Alteran stores and serves one account's repo. It does not provide hosted
moderation administration, public report triage, or labeler/Ozone operations.
If a deployment needs report handling or moderation workflows, route those to
an external labeler, Ozone-style service, application service, or operator
contact process.

The AppView/Ozone proxy support in Alteran is for configured external services;
it should not be treated as local moderation infrastructure.

### Unsupported Route Contract

The explicit unsupported route set is documented in [`API.md`](API.md) and
tested in `tests/unsupported-routes.test.ts`. That set currently covers public
signup, invites, signup queue helpers, selected temp account-management
methods, and the `com.atproto.admin.*` prefix.

Do not add new public account, moderation-admin, report-triage, or ToS
acceptance routes without first changing this boundary document, adding tests,
and deciding how the single-user product target changes.
