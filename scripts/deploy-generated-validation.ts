type Configuration = Readonly<Record<string, unknown>>;

export const UNSUPPORTED_ARRAY_FIELDS = [
  "workflows",
  "send_email",
  "vectorize",
  "ai_search_namespaces",
  "ai_search",
  "hyperdrive",
  "analytics_engine_datasets",
  "dispatch_namespaces",
  "mtls_certificates",
  "pipelines",
  "worker_loaders",
  "ratelimits",
  "vpc_services",
  "vpc_networks",
  "artifacts",
  "unsafe_hello_world",
  "flagship",
  "tail_consumers",
  "streaming_tail_consumers",
  "containers",
] as const;

// Wrangler's normalized view can drop fields from a redirected configuration.
// Inspect the generated JSON directly and reject new fields until reviewed.
const GENERATED_FIELDS = new Set([
  "account_id",
  "assets",
  "compatibility_date",
  "compatibility_flags",
  "configPath",
  "definedEnvironments",
  "dev",
  "jsx_factory",
  "jsx_fragment",
  "legacy_env",
  "main",
  "migrations",
  "name",
  "no_bundle",
  "observability",
  "previews",
  "rules",
  "targetEnvironment",
  "topLevelName",
  "userConfigPath",
  "vars",
  "triggers",
  "python_modules",
  "d1_databases",
  "r2_buckets",
  "kv_namespaces",
  "durable_objects",
  "secrets_store_secrets",
  "services",
  "queues",
  "unsafe",
  "cloudchamber",
  "logfwdr",
  "build",
  "wasm_modules",
  "text_blobs",
  "data_blobs",
  "routes",
  "route",
  "workers_dev",
  "preview_urls",
  "tsconfig",
  "limits",
  "placement",
  "define",
  "minify",
  "keep_names",
  "first_party_worker",
  "logpush",
  "upload_source_maps",
  "cache",
  "compliance_region",
  "send_metrics",
  "keep_vars",
  "alias",
  "site",
  "find_additional_modules",
  "preserve_file_names",
  "base_dir",
  ...UNSUPPORTED_ARRAY_FIELDS,
]);

const UNSUPPORTED_SINGLE_FIELDS = [
  "browser",
  "ai",
  "images",
  "stream",
  "media",
  "version_metadata",
] as const;

export function unsupportedResourceConfiguration(
  configuration: Configuration,
): boolean {
  if (
    UNSUPPORTED_ARRAY_FIELDS.some((key) => !emptyArray(configuration[key])) ||
    UNSUPPORTED_SINGLE_FIELDS.some((key) => configuration[key] !== undefined) ||
    !emptyObject(configuration.unsafe) ||
    !emptyObject(configuration.cloudchamber) ||
    !emptyObject(configuration.site) ||
    !safeBuild(configuration.build) ||
    !emptyObject(configuration.wasm_modules) ||
    !emptyObject(configuration.text_blobs) ||
    !emptyObject(configuration.data_blobs)
  ) return true;
  const queues = object(configuration.queues);
  if (
    !queues ||
    Object.keys(queues).some((key) =>
      !["producers", "consumers"].includes(key)
    ) ||
    !emptyArray(queues.producers) || !emptyArray(queues.consumers)
  ) return true;
  const logForwarder = configuration.logfwdr === undefined
    ? { bindings: [] }
    : object(configuration.logfwdr);
  return !logForwarder ||
    Object.keys(logForwarder).some((key) => key !== "bindings") ||
    !emptyArray(logForwarder.bindings);
}

export function invalidGeneratedFields(configuration: Configuration): boolean {
  if (Object.keys(configuration).some((key) => !GENERATED_FIELDS.has(key))) {
    return true;
  }
  return unsupportedResourceConfiguration(configuration) ||
    !isLocalSequencer(configuration.durable_objects);
}

export function generatedTargetsMatchSource(
  raw: Configuration,
  source: Configuration,
): boolean {
  return [
    "name",
    "account_id",
    "vars",
    "d1_databases",
    "r2_buckets",
    "kv_namespaces",
    "durable_objects",
    "secrets_store_secrets",
    "services",
    "migrations",
    "observability",
  ].every((key) => canonical(raw[key]) === canonical(source[key]));
}

export function isLocalSequencer(value: unknown): boolean {
  const objects = object(value);
  if (
    !objects || Object.keys(objects).length !== 1 ||
    !Array.isArray(objects.bindings) ||
    objects.bindings.length !== 1
  ) return false;
  const sequencer = object(objects.bindings[0]);
  return !!sequencer && Object.keys(sequencer).length === 2 &&
    sequencer.name === "ALTERAN_SEQUENCER" &&
    sequencer.class_name === "Sequencer";
}

function object(value: unknown): Configuration | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Configuration
    : null;
}

function emptyArray(value: unknown): boolean {
  return value === undefined || (Array.isArray(value) && value.length === 0);
}

function emptyObject(value: unknown): boolean {
  return value === undefined ||
    (object(value) !== null && Object.keys(object(value) ?? {}).length === 0);
}

function safeBuild(value: unknown): boolean {
  if (value === undefined) return true;
  const build = object(value);
  return !!build && build.command === undefined &&
    Object.keys(build).every((key) =>
      ["command", "watch_dir", "cwd"].includes(key)
    );
}

function canonical(value: unknown): string | undefined {
  return JSON.stringify(value, (_key, item: unknown) => {
    const values = object(item);
    return values
      ? Object.fromEntries(
        Object.entries(values).sort(([left], [right]) =>
          left.localeCompare(right)
        ),
      )
      : item;
  });
}
