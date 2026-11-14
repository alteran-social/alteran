# Deployment

Astro 6 selects the Cloudflare environment during the build. The generated
Wrangler configuration is flattened for that environment. Passing `--env` only
to a later deploy command does not retarget an existing build.

## Production

Configure the `production` environment in `wrangler.jsonc` before running
`deno task deploy`:

- Set its D1 `ALTERAN_DB` binding to the intended database UUID and its R2
  `ALTERAN_BLOBS` binding to the intended bucket name. The checked-in D1 ID is a
  placeholder.
- Set production `vars.PDS_DID`, `vars.PDS_HANDLE` and `vars.PDS_HOSTNAME` to
  the intended identity. The checked-in values name an existing identity; forks
  must replace them when appropriate. Do not also configure these names as
  Secrets Store bindings. Check existing remote Worker secrets for conflicts
  separately: local preflight cannot inspect or establish their precedence.
- Add a `SESSION` KV namespace binding with its existing namespace ID. Astro 6
  adds this binding for its session driver; an omitted ID can cause Wrangler to
  provision a namespace automatically.
- Set an account ID in the production configuration or supply the intended
  `CLOUDFLARE_ACCOUNT_ID` in the environment. If both are present, they must
  match. Configure the credentials and secrets for that account separately.
- Review the configured Durable Object migration history against the actual
  Worker before changing it. Wrangler 4.91 reports the checked-in
  `modified_classes` field as unsupported, so the preflight refuses it.

Configure identity values as strings and credentials as strings or supported
Secret Store bindings; see [Configuration](CONFIGURATION.md) for supported
fields. An invalid value such as a number or boolean is rejected; it does not
select a fallback credential. An absent optional session secret can still use
the D1-generated session key.

The task builds a private snapshot of the project with
`CLOUDFLARE_ENV=production`, then checks the generated Wrangler redirect and
configuration against the named source environment. It refuses missing or
placeholder resource IDs, implicit provisioning, unexpected bindings,
conflicting account/environment overrides, unsupported migration fields, and
private-protocol invocation logs or traces. It runs the redirected Wrangler
deploy in strict mode with automatic provisioning disabled. The task does not
accept extra Wrangler arguments that could change its target or prompt
interactively; configure credentials before running it. It rejects unsupported
or unknown generated configuration fields, nonempty unsafe configuration, and
Durable Object bindings other than one local `ALTERAN_SEQUENCER`.

The snapshot includes user and ignored project files, including environment
files, while excluding `.git`, `.wrangler`, `.astro`, `dist`, `node_modules`,
`.direnv`, `.devenv`, `.codex`, `.agents`, `.aws`, `atproto`, and `social-app`
at the project root. Dependencies are linked from the project. A symlink
pointing outside the snapshot is rejected. The temporary directory is private
and removed after the command; an abruptly terminated process may leave it
behind. Run the task from a trusted workspace and do not change its source
files, linked dependencies, or private snapshot while it runs. The snapshot does
not defend against another process with write access modifying files after
validation.

The preflight compares local configuration only. It cannot prove that an ID
exists, belongs to the intended Cloudflare account, has the right secrets, or
contains the expected data. Verify the account, Worker, D1, R2, KV, and Durable
Object migration state independently before deployment. No D1 or R2 data is
rolled back when a Worker is rolled back. If the deploy command fails after it
starts, check the remote Worker deployment before retrying: its outcome may be
unknown.

The updated Worker rejects older-format JWTs. Affected clients must authenticate
again. During rollout, replace or drain every older Worker version before
relying on that behavior; a rollback to an older Worker can restore its previous
verification behavior. Current non-OAuth refresh sessions continue to use the
existing refresh-table token kind.

`deno task db:apply` and `deno task db:apply:local` target the dev D1 binding
locally. `deno task db:apply:production` targets production remotely; verify its
account, database and backup first. `deno task db:reset:local` refuses because
Wrangler's default local D1 state can be shared across databases. No local D1
reset procedure is automated; migration files must not be deleted as a reset.

## Other environments and integrations

Build each named environment separately, for example:

```sh
CLOUDFLARE_ENV=staging deno task build
```

Inspect that build's generated configuration and target before using a separate
staging deployment workflow. The production task does not deploy staging or
development. Direct Wrangler deployment commands bypass its preflight.

A release workflow should run tests, build and verify staging for the selected
environment, perform smoke tests, then deploy and monitor production.

Applications consuming Alteran as an Astro integration use their own build and
Wrangler configuration; this repository's task cannot guard their deployment.
They must select their Cloudflare environment at build time and verify their own
bindings and deployment target.

Wrangler secret and D1 migration commands do not use the generated deploy
redirect in the same way as `wrangler deploy`. Select their intended environment
and target separately; a production build alone does not select those commands.

## Rollback

After verifying the account and Worker, use the Cloudflare dashboard or
`wrangler rollback` to restore a previously deployed Worker version. See
[Cloudflare's rollback instructions](https://developers.cloudflare.com/workers/versions-and-deployments/rollbacks/)
for version and resource limitations. Check data compatibility with the older
version; rolling back Worker code does not roll back connected resources.

Cloudflare documents
[Vite environment selection](https://developers.cloudflare.com/workers/vite-plugin/reference/cloudflare-environments/)
and
[Wrangler's generated configuration](https://developers.cloudflare.com/workers/wrangler/configuration/#generated-wrangler-configuration).
