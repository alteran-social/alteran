/// <reference types="astro/client" />

import type {
  D1Database,
  DurableObjectNamespace,
  ExecutionContext,
  R2Bucket,
} from "@cloudflare/workers-types";

// Minimal Secret Store binding interface. Cloudflare exposes each bound secret
// as an object with an async `get()` that returns the secret value.
// If @cloudflare/workers-types defines this already, our local type is compatible.
export interface SecretsStoreSecret {
  get(): Promise<string>;
}

declare global {
  interface Env {
    DB: D1Database;
    BLOBS: R2Bucket;
    SEQUENCER?: DurableObjectNamespace;
    ASSETS?: {
      fetch: (req: Request | string) => Promise<Response>;
    };
    // Secrets can be provided either as Wrangler Secrets (string)
    // or via Secret Store bindings (SecretsStoreSecret).
    PDS_HANDLE?: string | SecretsStoreSecret;
    PDS_DID?: string | SecretsStoreSecret;
    PDS_HOSTNAME?: string;
    PDS_ALLOWED_MIME?: string;
    USER_PASSWORD?: string | SecretsStoreSecret;
    PDS_MAX_BLOB_SIZE?: string;
    PDS_BLOB_QUOTA_BYTES?: string;
    REFRESH_TOKEN?: string | SecretsStoreSecret;
    REFRESH_TOKEN_SECRET?: string | SecretsStoreSecret;
    SESSION_JWT_SECRET?: string | SecretsStoreSecret;
    PDS_ACCESS_TTL_SEC?: string;
    PDS_REFRESH_TTL_SEC?: string;
    // secp256k1 signing private key (hex or base64 32 bytes) used for commits and service-auth
    REPO_SIGNING_KEY?: string | SecretsStoreSecret;
    PDS_PLC_ROTATION_KEY?: string | SecretsStoreSecret;
    PDS_RATE_LIMIT_PER_MIN?: string;
    PDS_MAX_JSON_BYTES?: string;
    PDS_CORS_ORIGIN?: string;
    PDS_SEQ_WINDOW?: string;
    ENVIRONMENT?: string;
    PDS_BSKY_APP_VIEW_URL?: string;
    PDS_BSKY_APP_VIEW_DID?: string;
    PDS_BSKY_APP_VIEW_CDN_URL_PATTERN?: string;
    PDS_BSKY_CHAT_URL?: string;
    PDS_BSKY_CHAT_DID?: string;
    PDS_OZONE_URL?: string;
    PDS_OZONE_DID?: string;
    PDS_LINK_PRIVACY?: string;
    PDS_LINK_TOS?: string;
    PDS_CONTACT_EMAIL?: string;
    // Relay crawl configuration
    PDS_RELAY_HOSTS?: string; // CSV of relay hostnames (no scheme). Default: bsky.network
    PDS_RELAY_NOTIFY?: string; // 'false' to disable auto notify
  }

  namespace App {
    interface Locals {
      runtime: {
        env: Env;
        ctx: ExecutionContext;
        request: Request;
      };
      requestId?: string;
    }
  }
}

export {};

export type Env = globalThis.Env;
export type PdsLocals = globalThis.App.Locals;
