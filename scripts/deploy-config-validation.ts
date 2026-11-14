import {
  isLocalSequencer,
  unsupportedResourceConfiguration,
} from "./deploy-generated-validation.ts";

type Configuration = Readonly<Record<string, unknown>>;

const GENERATED_FIELDS = new Set([
  "configPath",
  "userConfigPath",
  "rules",
  "main",
  "assets",
  "no_bundle",
  "previews",
]);
const MIGRATION_FIELDS = new Set([
  "tag",
  "new_classes",
  "new_sqlite_classes",
  "renamed_classes",
  "deleted_classes",
]);
const HEX_ID = /^[a-f0-9]{32}$/i;
const D1_ID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;

export type DeploymentValidation =
  | { readonly tag: "valid"; readonly accountId: string }
  | { readonly tag: "invalid"; readonly reason: string };

/** Compare the named source environment with the actual redirected build. */
export function validateDeploymentConfig(
  source: Configuration,
  generated: Configuration,
  ambientAccount: string | undefined,
): DeploymentValidation {
  const sourceAccount = typeof source.account_id === "string"
    ? source.account_id
    : undefined;
  if (sourceAccount && ambientAccount && sourceAccount !== ambientAccount) {
    return invalid("Conflicting account IDs");
  }
  const accountId = sourceAccount ?? ambientAccount;
  if (!accountId || !validId(accountId, HEX_ID)) {
    return invalid("Configure the intended Cloudflare account ID");
  }
  if (
    source.targetEnvironment !== "production" ||
    generated.targetEnvironment !== "production" ||
    !configuredName(source.name) || generated.name !== source.name ||
    !configuredName(source.topLevelName) ||
    generated.topLevelName !== source.topLevelName ||
    record(source.vars)?.ENVIRONMENT !== "production"
  ) return invalid("Production build selection does not match");
  const variables = record(source.vars);
  if (
    !variables || !validDid(variables.PDS_DID) ||
    !validHost(variables.PDS_HANDLE) ||
    !validHost(variables.PDS_HOSTNAME)
  ) return invalid("Configure production identity variables");
  if (
    unsupportedResourceConfiguration(source) ||
    unsupportedResourceConfiguration(generated)
  ) {
    return invalid("Unsupported production resource binding");
  }
  const observability = record(source.observability);
  if (
    record(observability?.logs)?.invocation_logs !== false ||
    record(observability?.traces)?.enabled !== false
  ) {
    return invalid("Configure private protocol logging settings");
  }
  for (
    const key of new Set([...Object.keys(source), ...Object.keys(generated)])
  ) {
    if (
      !GENERATED_FIELDS.has(key) &&
      canonical(source[key]) !== canonical(generated[key])
    ) {
      return invalid("Generated configuration does not match production");
    }
  }
  if (
    source.no_bundle !== undefined || generated.no_bundle !== true ||
    !empty(source.rules) ||
    canonical(generated.rules) !==
      canonical([{ type: "ESModule", globs: ["**/*.js", "**/*.mjs"] }]) ||
    source.assets !== undefined ||
    canonical(generated.assets) !==
      canonical({ binding: "ASSETS", directory: "../client" }) ||
    source.previews !== undefined ||
    canonical(generated.previews) !==
      canonical({ kv_namespaces: [{ binding: "SESSION" }] })
  ) {
    return invalid("Unsupported generated build configuration");
  }
  const databases = records(source.d1_databases),
    buckets = records(source.r2_buckets),
    namespaces = records(source.kv_namespaces);
  if (
    !databases || !buckets || !namespaces || !uniqueBindings(databases) ||
    !uniqueBindings(buckets) ||
    !uniqueBindings(namespaces) ||
    databases.filter((entry) => entry.binding === "ALTERAN_DB").length !== 1 ||
    buckets.filter((entry) => entry.binding === "ALTERAN_BLOBS").length !== 1 ||
    namespaces.filter((entry) => entry.binding === "SESSION").length !== 1 ||
    databases.some((entry) =>
      typeof entry.database_id !== "string" ||
      !validId(entry.database_id, D1_ID) ||
      (entry.database_name !== undefined &&
        !configuredName(entry.database_name))
    ) ||
    buckets.some((entry) => !configuredName(entry.bucket_name)) ||
    namespaces.some((entry) =>
      typeof entry.id !== "string" || !validId(entry.id, HEX_ID)
    )
  ) {
    return invalid("Configure explicit production D1, R2 and KV resources");
  }
  const objects = records(record(source.durable_objects)?.bindings);
  if (
    !objects || !isLocalSequencer(source.durable_objects)
  ) {
    return invalid("Configure the production Sequencer binding");
  }
  const migrations = records(source.migrations);
  if (
    !migrations ||
    migrations.some((entry) =>
      Object.keys(entry).some((key) => !MIGRATION_FIELDS.has(key)) ||
      !configuredName(entry.tag)
    )
  ) return invalid("Review unsupported Durable Object migration fields");
  const secrets = records(source.secrets_store_secrets),
    services = records(source.services);
  if (
    !secrets || !services || !uniqueBindings(secrets) ||
    !uniqueBindings(services) ||
    secrets.some((entry) =>
      typeof entry.store_id !== "string" || !validId(entry.store_id, HEX_ID) ||
      !configuredName(entry.secret_name)
    ) || services.some((entry) => !configuredName(entry.service)) ||
    !uniqueBindings([
      ...databases,
      ...buckets,
      ...namespaces,
      ...objects,
      ...secrets,
      ...services,
      ...Object.keys(variables).map((name) => ({ name })),
      { name: "ASSETS" },
    ])
  ) {
    return invalid("Configure explicit production resource bindings");
  }
  return { tag: "valid", accountId };
}

function validDid(value: unknown): boolean {
  return typeof value === "string" &&
    /^did:[a-z0-9]+:[a-z0-9._:%-]+$/i.test(value) &&
    !/^did:example:/i.test(value);
}

function validHost(value: unknown): boolean {
  return typeof value === "string" && value.length <= 253 &&
    /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i
      .test(value) &&
    !/(?:^|\.)(?:example\.(?:com|org|net)|invalid|test)$/i.test(value);
}

function configuredName(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 255 &&
    !/^(?:your[-_]|placeholder(?:$|[-_])|example(?:$|[-_])|replace(?:me)?(?:$|[-_])|change(?:me)?(?:$|[-_])|todo(?:$|[-_])|<|\$\{)/i
      .test(value) &&
    value !== "local-dev";
}

function validId(value: string, pattern: RegExp): boolean {
  return pattern.test(value) && !/^0+$/.test(value.replaceAll("-", ""));
}

function record(value: unknown): Configuration | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Configuration
    : null;
}

function records(value: unknown): readonly Configuration[] | null {
  if (!Array.isArray(value)) return null;
  const result = value.map(record);
  return result.every((entry) => entry !== null)
    ? result as Configuration[]
    : null;
}

function uniqueBindings(values: readonly Configuration[]): boolean {
  const names = values.map((entry) => entry.binding ?? entry.name);
  return names.every(configuredName) && new Set(names).size === names.length;
}

function empty(value: unknown): boolean {
  return value === undefined || (Array.isArray(value) && value.length === 0);
}

function canonical(value: unknown): string | undefined {
  return JSON.stringify(value, (_key, item: unknown) => {
    const object = record(item);
    return object
      ? Object.fromEntries(
        Object.entries(object).sort(([a], [b]) => a.localeCompare(b)),
      )
      : item;
  });
}

function invalid(reason: string): DeploymentValidation {
  return { tag: "invalid", reason };
}
