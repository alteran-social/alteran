import { defineConfig, envField } from "astro/config";
import cloudflare from "@astrojs/cloudflare";
import icon from "astro-icon";
import alteran from "./index.js";

// https://astro.build/config
export default defineConfig({
  output: "server",
  adapter: cloudflare({ mode: "advanced", imageService: "custom" }),
  server: { host: true },
  image: {
    service: {
      entrypoint: "@astrojs/cloudflare/image-service",
    },
  },
  integrations: [
    icon(),
    alteran({ debugRoutes: true, includeRootEndpoint: true }),
  ],
  env: {
    schema: {
      PDS_DID: envField.string({ context: "server", access: "secret" }),
      PDS_HANDLE: envField.string({ context: "server", access: "secret" }),
      USER_PASSWORD: envField.string({ context: "server", access: "secret" }),
      ACCESS_TOKEN: envField.string({ context: "server", access: "secret" }),
      REFRESH_TOKEN: envField.string({ context: "server", access: "secret" }),
      PDS_ALLOWED_MIME: envField.string({
        context: "server",
        access: "secret",
        default: "image/jpeg,image/png,image/webp,image/gif,image/avif",
        optional: true,
      }),
      PDS_MAX_BLOB_SIZE: envField.string({
        context: "server",
        access: "secret",
        default: "5242880",
        optional: true,
      }),
      PDS_MAX_JSON_BYTES: envField.string({
        context: "server",
        access: "secret",
        default: "1048576",
        optional: true,
      }),
      PDS_RATE_LIMIT_PER_MIN: envField.string({
        context: "server",
        access: "secret",
        default: "1000",
        optional: true,
      }),
      PDS_CORS_ORIGIN: envField.string({
        context: "server",
        access: "secret",
        default: "*",
        optional: true,
      }),
      PDS_SEQ_WINDOW: envField.string({
        context: "server",
        access: "secret",
        default: "512",
        optional: true,
      }),
      ENVIRONMENT: envField.string({
        context: "server",
        access: "secret",
        default: "development",
        optional: true,
      }),
      PDS_HOSTNAME: envField.string({
        context: "server",
        access: "secret",
        optional: true,
      }),
      PDS_ACCESS_TTL_SEC: envField.string({
        context: "server",
        access: "secret",
        optional: true,
      }),
      PDS_REFRESH_TTL_SEC: envField.string({
        context: "server",
        access: "secret",
        optional: true,
      }),
      REPO_SIGNING_KEY: envField.string({
        context: "server",
        access: "secret",
        optional: true,
      }),
    },
  },
});
