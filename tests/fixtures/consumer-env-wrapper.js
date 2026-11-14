import app from "./entry.mjs";

export { Sequencer } from "./entry.mjs";

export default {
  async fetch(request, env, context) {
    const selection = request.headers.get("x-fixture-env");
    if (selection === "hostname-string" || selection === "hostname-store") {
      return app.fetch(request, {
        ...env,
        ALTERAN_DB: env.DB_A,
        PDS_HOSTNAME: selection === "hostname-string" ? "canonical.example" : {
          get: async () => {
            throw new Error("hostname-store-marker");
          },
        },
      }, context);
    }
    if (selection === "hostname-inherited" || selection === "hostname-hidden") {
      const selected = { ...env };
      const parent = {};
      if (selection === "hostname-inherited") {
        Object.setPrototypeOf(selected, parent);
      }
      const target = selection === "hostname-inherited" ? parent : selected;
      for (
        const [key, value] of Object.entries({
          PDS_HOSTNAME: "canonical.example",
          ALTERAN_DB: env.DB_A,
          ALTERAN_BLOBS: env.ALTERAN_BLOBS,
        })
      ) {
        delete selected[key];
        Object.defineProperty(target, key, {
          enumerable: false,
          get() {
            if (this !== selected) throw new Error("Wrong Env getter receiver");
            return value;
          },
        });
      }
      return app.fetch(request, selected, context);
    }
    if (selection !== "first" && selection !== "second") {
      return app.fetch(request, env, context);
    }
    const {
      USER_PASSWORD,
      SESSION_JWT_SECRET,
      REFRESH_TOKEN,
      REFRESH_TOKEN_SECRET,
      ...shared
    } = env;
    const selected = {
      ...shared,
      ALTERAN_DB: selection === "first" ? env.DB_A : env.DB_B,
      PDS_DID: "did:example:scoped",
      PDS_HANDLE: "test.example",
      TEST_LABEL: selection,
      ...(selection === "first"
        ? {
          USER_PASSWORD: env.FIXTURE_PASSWORD,
          SESSION_JWT_SECRET: env.FIXTURE_SESSION,
          REFRESH_TOKEN: env.FIXTURE_LEGACY,
        }
        : {}),
    };
    return app.fetch(request, selected, context);
  },
};
