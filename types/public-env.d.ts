import type {
  D1Database,
  DurableObjectNamespace,
  ExecutionContext,
  R2Bucket,
} from "@cloudflare/workers-types";

export type SecretsStoreSecret = {
  get(): Promise<string>;
};

export type Env = {
  ALTERAN_DB: D1Database;
  ALTERAN_BLOBS: R2Bucket;
  ALTERAN_SEQUENCER?: DurableObjectNamespace;
  ASSETS?: {
    fetch: (request: Request | string) => Promise<Response>;
  };
  PDS_HANDLE?: string | SecretsStoreSecret;
  PDS_DID?: string | SecretsStoreSecret;
  PDS_HOSTNAME?: string;
  PDS_EMAIL?: string;
  PDS_ALLOWED_MIME?: string;
  USER_PASSWORD?: string | SecretsStoreSecret;
  PDS_MAX_BLOB_SIZE?: string;
  PDS_BLOB_QUOTA_BYTES?: string;
  REFRESH_TOKEN?: string | SecretsStoreSecret;
  REFRESH_TOKEN_SECRET?: string | SecretsStoreSecret;
  SESSION_JWT_SECRET?: string | SecretsStoreSecret;
  PDS_ACCESS_TTL_SEC?: string;
  PDS_REFRESH_TTL_SEC?: string;
  REPO_SIGNING_KEY?: string | SecretsStoreSecret;
  PDS_PLC_ROTATION_KEY?: string | SecretsStoreSecret;
  PDS_RATE_LIMIT_PER_MIN?: string;
  PDS_MAX_JSON_BYTES?: string;
  PDS_CORS_ORIGIN?: string;
  PDS_SEQ_WINDOW?: string;
  PDS_WS_HIBERNATE?: string;
  ENVIRONMENT?: string;
  PDS_BSKY_APP_VIEW_URL?: string;
  PDS_BSKY_APP_VIEW_DID?: string;
  PDS_BSKY_APP_VIEW_CDN_URL_PATTERN?: string;
  PDS_APPVIEW_FORCE_FALLBACK?: string;
  PDS_BSKY_CHAT_URL?: string;
  PDS_BSKY_CHAT_DID?: string;
  PDS_OZONE_URL?: string;
  PDS_OZONE_DID?: string;
  PDS_LINK_PRIVACY?: string;
  PDS_LINK_TOS?: string;
  PDS_CONTACT_EMAIL?: string;
  PDS_RELAY_HOSTS?: string;
  PDS_RELAY_NOTIFY?: string;
  PDS_OAUTH_CLIENT_HOSTS?: string;
};

export type PdsLocals = {
  // Resolved environment bindings (Secret Store values materialized to strings).
  // Set by the alteran middleware on every request.
  env: Env;
  // Cloudflare ExecutionContext — Astro v6 surfaces it via `locals.cfContext`.
  cfContext: ExecutionContext;
  requestId?: string;
};
