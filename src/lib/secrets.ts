import type { Env } from "../env";
import type { SecretsStoreSecret } from "../../types/public-env";

const SECRET_KEYS = [
  "PDS_DID",
  "PDS_HANDLE",
  "USER_PASSWORD",
  "SESSION_JWT_SECRET",
  "REPO_SIGNING_KEY",
  "PDS_PLC_ROTATION_KEY",
] as const satisfies readonly (keyof Env)[];

// These values are read lazily, but their properties still need the same
// protected boundary when an Env is copied for a request.
const LAZY_CONFIG_KEYS = [
  "PDS_HOSTNAME",
  "PDS_SPACE_KEM_KEY",
] as const satisfies readonly (keyof Env)[];

const SENSITIVE_KEYS = new Set<PropertyKey>([
  ...SECRET_KEYS,
  ...LAZY_CONFIG_KEYS,
]);

const CREDENTIAL_KEYS = new Set<PropertyKey>([
  "USER_PASSWORD",
  "SESSION_JWT_SECRET",
  "REPO_SIGNING_KEY",
  "PDS_PLC_ROTATION_KEY",
  "PDS_SPACE_KEM_KEY",
]);

// Declared fields are captured even when a custom Env puts them on its
// prototype or marks them non-enumerable. Keep this exhaustive as Env grows.
const OTHER_ENV_KEYS = {
  ALTERAN_DB: true,
  ALTERAN_BLOBS: true,
  ALTERAN_SEQUENCER: true,
  ASSETS: true,
  PDS_EMAIL: true,
  PDS_ALLOWED_MIME: true,
  PDS_MAX_BLOB_SIZE: true,
  PDS_BLOB_QUOTA_BYTES: true,
  PDS_ACCESS_TTL_SEC: true,
  PDS_REFRESH_TTL_SEC: true,
  PDS_RATE_LIMIT_PER_MIN: true,
  PDS_MAX_JSON_BYTES: true,
  PDS_CORS_ORIGIN: true,
  PDS_SEQ_WINDOW: true,
  PDS_WS_HIBERNATE: true,
  ENVIRONMENT: true,
  PDS_BSKY_APP_VIEW_URL: true,
  PDS_BSKY_APP_VIEW_DID: true,
  PDS_BSKY_APP_VIEW_CDN_URL_PATTERN: true,
  PDS_APPVIEW_FORCE_FALLBACK: true,
  PDS_BSKY_CHAT_URL: true,
  PDS_BSKY_CHAT_DID: true,
  PDS_OZONE_URL: true,
  PDS_OZONE_DID: true,
  PDS_LINK_PRIVACY: true,
  PDS_LINK_TOS: true,
  PDS_CONTACT_EMAIL: true,
  PDS_RELAY_HOSTS: true,
  PDS_RELAY_NOTIFY: true,
  PDS_OAUTH_CLIENT_HOSTS: true,
} satisfies Record<
  Exclude<
    keyof Env,
    (typeof SECRET_KEYS)[number] | (typeof LAZY_CONFIG_KEYS)[number]
  >,
  true
>;

// Astro's Cloudflare adapter uses this binding in addition to Alteran's Env.
const ADAPTER_BINDING_KEYS = ["SESSION"] as const;

export class SecretResolutionError extends Error {
  constructor() {
    super("Secret binding could not be resolved");
    this.name = "SecretResolutionError";
  }
}

function isSecretStoreBinding(value: unknown): value is SecretsStoreSecret {
  return (
    !!value &&
    typeof value === "object" &&
    "get" in value &&
    typeof (value as { get: unknown }).get === "function"
  );
}

export async function resolveSecret(
  value: unknown,
): Promise<string | undefined> {
  if (value === undefined) return undefined;
  if (typeof value === "string") return value;
  try {
    if (isSecretStoreBinding(value)) {
      const secret: unknown = await value.get();
      if (typeof secret !== "string") throw new SecretResolutionError();
      return secret;
    }
  } catch {
    throw new SecretResolutionError();
  }
  throw new SecretResolutionError();
}

function readEnvValue(env: Env, key: PropertyKey): unknown {
  try {
    return Reflect.get(env, key);
  } catch {
    throw new SecretResolutionError();
  }
}

function envHas(env: Env, key: PropertyKey): boolean {
  try {
    return Reflect.has(env, key);
  } catch {
    throw new SecretResolutionError();
  }
}

function rejectBlankCredential(key: PropertyKey, value: unknown): void {
  if (
    CREDENTIAL_KEYS.has(key) && typeof value === "string" && value.trim() === ""
  ) {
    throw new SecretResolutionError();
  }
}

function validateLazyValue(
  key: (typeof LAZY_CONFIG_KEYS)[number],
  value: unknown,
): void {
  if (value === undefined) return;
  if (typeof value === "string") {
    rejectBlankCredential(key, value);
    return;
  }
  if (key === "PDS_HOSTNAME") throw new SecretResolutionError();
  try {
    if (isSecretStoreBinding(value)) return;
  } catch {
    throw new SecretResolutionError();
  }
  throw new SecretResolutionError();
}

/**
 * Return a shallow-cloned Env with eagerly used secrets materialized.
 * The Spaces KEM binding stays lazy; ordinary bindings retain their values.
 */
export async function resolveEnvSecrets<E extends Env>(env: E): Promise<E> {
  const resolved: Record<PropertyKey, unknown> = {};
  const enumerableSensitive = new Set<PropertyKey>();

  // Copy ordinary bindings with the same own-enumerable value semantics as
  // object spread. Sensitive getters are read separately inside the guard.
  let ownKeys: PropertyKey[];
  try {
    ownKeys = Reflect.ownKeys(env);
  } catch {
    throw new SecretResolutionError();
  }
  for (const key of ownKeys) {
    let descriptor: PropertyDescriptor | undefined;
    try {
      descriptor = Reflect.getOwnPropertyDescriptor(env, key);
    } catch {
      throw new SecretResolutionError();
    }
    if (!descriptor?.enumerable) continue;
    if (SENSITIVE_KEYS.has(key)) {
      enumerableSensitive.add(key);
      continue;
    }
    Object.defineProperty(resolved, key, {
      value: readEnvValue(env, key),
      writable: true,
      enumerable: true,
      configurable: true,
    });
  }

  for (const key of [...Object.keys(OTHER_ENV_KEYS), ...ADAPTER_BINDING_KEYS]) {
    if (Object.hasOwn(resolved, key) || !envHas(env, key)) continue;
    const value = readEnvValue(env, key);
    if (value === undefined) continue;
    Object.defineProperty(resolved, key, {
      value,
      writable: true,
      enumerable: true,
      configurable: true,
    });
  }

  await Promise.all(
    SECRET_KEYS.map(async (key) => {
      const original = readEnvValue(env, key);
      const value = await resolveSecret(original);
      rejectBlankCredential(key, value);
      if (value !== undefined || enumerableSensitive.has(key)) {
        Object.defineProperty(resolved, key, {
          value,
          writable: true,
          enumerable: true,
          configurable: true,
        });
      }
    }),
  );

  for (const key of LAZY_CONFIG_KEYS) {
    const value = readEnvValue(env, key);
    validateLazyValue(key, value);
    if (value === undefined && !enumerableSensitive.has(key)) continue;
    Object.defineProperty(resolved, key, {
      value,
      writable: true,
      enumerable: true,
      configurable: true,
    });
  }

  return resolved as E;
}

export async function getRuntimeString<K extends keyof Env>(
  env: Env,
  key: K,
  fallback?: string,
): Promise<string | undefined> {
  const sensitive = SENSITIVE_KEYS.has(key);
  const current = readEnvValue(env, key);
  if (key === "PDS_HOSTNAME") validateLazyValue(key, current);
  if (
    !sensitive && (typeof current === "number" || typeof current === "boolean")
  ) {
    return String(current);
  }
  const value = await resolveSecret(current);
  rejectBlankCredential(key, value);
  if (typeof value === "string" && value !== "") return value;
  return fallback;
}
