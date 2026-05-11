import { setGetEnv } from "astro/env/setup";
import type { Env } from "../env";
import type { SecretsStoreSecret } from "../../types/env";

const SECRET_KEYS = [
  "PDS_DID",
  "PDS_HANDLE",
  "USER_PASSWORD",
  "REFRESH_TOKEN",
  "REFRESH_TOKEN_SECRET",
  "SESSION_JWT_SECRET",
  "REPO_SIGNING_KEY",
  "PDS_PLC_ROTATION_KEY",
] as const satisfies readonly (keyof Env)[];

function isSecretStoreBinding(value: unknown): value is SecretsStoreSecret {
  return (
    !!value &&
    typeof value === "object" &&
    "get" in value &&
    typeof (value as { get: unknown }).get === "function"
  );
}

export async function resolveSecret(
  value: string | SecretsStoreSecret | undefined,
): Promise<string | undefined> {
  if (value === undefined) return undefined;
  if (typeof value === "string") return value;
  if (isSecretStoreBinding(value)) return value.get();
  return undefined;
}

/**
 * Return a shallow-cloned Env where all known secret fields are materialized to strings.
 * Non-secret bindings (DB, BLOBS, SEQUENCER, vars) are preserved as-is.
 */
export async function resolveEnvSecrets<E extends Env>(env: E): Promise<E> {
  const resolved = { ...env } as Record<string, unknown>;

  await Promise.all(
    SECRET_KEYS.map(async (key) => {
      const value = await resolveSecret(env[key]);
      if (value !== undefined) {
        resolved[key as string] = value;
      }
    }),
  );

  setGetEnv((key) => {
    const local = resolved[key];
    if (typeof local === "string") return local;
    if (typeof local === "number" || typeof local === "boolean")
      return String(local);
    const fallback = process.env[key];
    return typeof fallback === "string" ? fallback : undefined;
  });

  return resolved as E;
}

type AstroGetSecret = (key: string) => string | undefined;

let astroGetSecret: AstroGetSecret | null | undefined;

async function loadAstroGetSecret(): Promise<AstroGetSecret | null> {
  if (astroGetSecret !== undefined) return astroGetSecret;
  try {
    const mod = await import("astro:env/server");
    astroGetSecret = mod.getSecret as AstroGetSecret;
  } catch {
    astroGetSecret = null;
  }
  return astroGetSecret;
}

export async function getRuntimeString<K extends keyof Env>(
  env: Env,
  key: K,
  fallback?: string,
): Promise<string | undefined> {
  const current = env[key];
  if (typeof current === "string" && current !== "") {
    return current;
  }

  const secretFn = await loadAstroGetSecret();
  if (secretFn) {
    try {
      const value = secretFn(String(key));
      if (typeof value === "string" && value !== "") {
        return value;
      }
    } catch (error) {
      if (fallback === undefined) {
        throw error;
      }
    }
  }

  return fallback;
}
