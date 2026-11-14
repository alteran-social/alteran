import { describe, it } from "@std/testing/bdd";
import { expect } from "@std/expect";
import { validateDeploymentConfig } from "../scripts/deploy-config-validation.ts";
import {
  generatedTargetsMatchSource,
  invalidGeneratedFields,
} from "../scripts/deploy-generated-validation.ts";
import { publicPreflightMessage } from "../scripts/deploy-diagnostics.ts";

function configurations() {
  const source: Record<string, unknown> = {
    name: "alteran-production",
    topLevelName: "alteran",
    targetEnvironment: "production",
    account_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    vars: {
      ENVIRONMENT: "production",
      PDS_DID: "did:plc:abcdefghijklmnopqrstuvwx",
      PDS_HANDLE: "pds.example.dev",
      PDS_HOSTNAME: "pds.example.dev",
    },
    compatibility_flags: ["nodejs_compat"],
    rules: [],
    d1_databases: [{
      binding: "ALTERAN_DB",
      database_id: "11111111-1111-4111-8111-111111111111",
    }],
    r2_buckets: [{
      binding: "ALTERAN_BLOBS",
      bucket_name: "alteran-production",
    }],
    kv_namespaces: [{
      binding: "SESSION",
      id: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    }],
    durable_objects: {
      bindings: [{ name: "ALTERAN_SEQUENCER", class_name: "Sequencer" }],
    },
    migrations: [{ tag: "v1", new_classes: ["Sequencer"] }],
    queues: { producers: [], consumers: [] },
    services: [],
    secrets_store_secrets: [],
    observability: {
      logs: { invocation_logs: false },
      traces: { enabled: false },
    },
  };
  const generated = structuredClone(source);
  Object.assign(generated, {
    rules: [{ type: "ESModule", globs: ["**/*.js", "**/*.mjs"] }],
    assets: { binding: "ASSETS", directory: "../client" },
    no_bundle: true,
    previews: { kv_namespaces: [{ binding: "SESSION" }] },
  });
  return { source, generated };
}

describe("production deployment configuration", () => {
  it("accepts matching explicit production bindings", () => {
    const { source, generated } = configurations();
    expect(validateDeploymentConfig(source, generated, undefined).tag).toBe(
      "valid",
    );
    delete source.account_id;
    delete generated.account_id;
    expect(
      validateDeploymentConfig(
        source,
        generated,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      ).tag,
    ).toBe("valid");
  });

  it("rejects another build environment and mismatched bindings", () => {
    for (
      const [key, value] of [
        ["targetEnvironment", undefined],
        ["name", "alteran"],
        ["d1_databases", [{
          binding: "ALTERAN_DB",
          database_id: "22222222-2222-4222-8222-222222222222",
        }]],
        ["r2_buckets", [{
          binding: "ALTERAN_BLOBS",
          bucket_name: "alteran-staging",
        }]],
        ["vars", { ENVIRONMENT: "staging" }],
        ["compatibility_flags", []],
        ["kv_namespaces", [{
          binding: "SESSION",
          id: "cccccccccccccccccccccccccccccccc",
        }]],
      ] as const
    ) {
      const { source, generated } = configurations();
      generated[key] = value;
      expect(validateDeploymentConfig(source, generated, undefined).tag).toBe(
        "invalid",
      );
    }
  });

  it("refuses missing IDs, automatic provisioning and unsupported migrations", () => {
    for (
      const [key, value] of [
        ["account_id", undefined],
        ["account_id", "00000000000000000000000000000000"],
        ["d1_databases", [{
          binding: "ALTERAN_DB",
          database_id: "YOUR_PRODUCTION_D1_ID",
        }]],
        ["kv_namespaces", [{ binding: "SESSION" }]],
        ["r2_buckets", [{ binding: "ALTERAN_BLOBS" }]],
        ["r2_buckets", [{
          binding: "ALTERAN_BLOBS",
          bucket_name: "your-production-bucket",
        }]],
        ["name", "placeholder-worker"],
        ["migrations", [{ tag: "v2", modified_classes: ["Sequencer"] }]],
        ["observability", {
          logs: { invocation_logs: true },
          traces: { enabled: false },
        }],
        ["queues", { producers: [{ binding: "QUEUE" }], consumers: [] }],
      ] as const
    ) {
      const { source, generated } = configurations();
      source[key] = value;
      generated[key] = structuredClone(value);
      expect(validateDeploymentConfig(source, generated, undefined).tag).toBe(
        "invalid",
      );
    }
    const { source, generated } = configurations();
    expect(
      validateDeploymentConfig(
        source,
        generated,
        "cccccccccccccccccccccccccccccccc",
      ).tag,
    ).toBe("invalid");
  });

  it("rejects generated-only resources and accepts explicitly configured secret bindings", () => {
    const extra = configurations();
    extra.generated.kv_namespaces = [
      ...extra.generated.kv_namespaces as unknown[],
      { binding: "OTHER" },
    ];
    expect(
      validateDeploymentConfig(extra.source, extra.generated, undefined).tag,
    ).toBe("invalid");
    const explicit = configurations();
    explicit.source.secrets_store_secrets = [{
      binding: "MY_SECRET",
      store_id: "cccccccccccccccccccccccccccccccc",
      secret_name: "my-secret",
    }];
    explicit.generated.secrets_store_secrets = structuredClone(
      explicit.source.secrets_store_secrets,
    );
    expect(
      validateDeploymentConfig(explicit.source, explicit.generated, undefined)
        .tag,
    ).toBe("valid");
  });

  it("rejects unsupported resource categories and unsafe configuration even when both views agree", () => {
    const entries: readonly (readonly [string, unknown])[] = [
      ["browser", { binding: "BROWSER" }],
      ["ai", { binding: "AI" }],
      ["images", { binding: "IMAGES" }],
      ["stream", { binding: "STREAM" }],
      ["media", { binding: "MEDIA" }],
      ["version_metadata", { binding: "VERSION" }],
      ["ai_search", [{ binding: "SEARCH" }]],
      ["artifacts", [{ binding: "ARTIFACTS" }]],
      ["flagship", [{ binding: "FLAGS" }]],
      ["unsafe", { bindings: [] }],
      ["unsafe", { metadata: { bindings: [] } }],
      ["unsafe", { bindings: [{ name: "EMAIL", type: "send_email" }] }],
      ["logfwdr", { bindings: [{ name: "LOG" }] }],
      ["build", { command: "change-output" }],
    ];
    for (const [key, value] of entries) {
      const { source, generated } = configurations();
      source[key] = value;
      generated[key] = structuredClone(value);
      expect(validateDeploymentConfig(source, generated, undefined).tag).toBe(
        "invalid",
      );
      expect(invalidGeneratedFields(generated)).toBe(true);
    }
    const unknown = configurations();
    unknown.generated.future_binding = { binding: "FUTURE" };
    expect(invalidGeneratedFields(unknown.generated)).toBe(true);
  });

  it("requires a single local Sequencer and explicit, non-placeholder production identity", () => {
    for (
      const bindings of [
        [{
          name: "ALTERAN_SEQUENCER",
          class_name: "Sequencer",
          script_name: "other-worker",
        }],
        [{
          name: "ALTERAN_SEQUENCER",
          class_name: "Sequencer",
          environment: "staging",
        }],
        [{ name: "ALTERAN_SEQUENCER", class_name: "Sequencer" }, {
          name: "OTHER",
          class_name: "Other",
        }],
      ]
    ) {
      const { source, generated } = configurations();
      source.durable_objects = { bindings };
      generated.durable_objects = { bindings: structuredClone(bindings) };
      expect(validateDeploymentConfig(source, generated, undefined).tag).toBe(
        "invalid",
      );
      expect(invalidGeneratedFields(generated)).toBe(true);
    }
    for (
      const [key, value] of [["PDS_DID", "did:example:placeholder"], [
        "PDS_HANDLE",
        "user.example.com",
      ], ["PDS_HOSTNAME", ""]] as const
    ) {
      const { source, generated } = configurations();
      const vars = { ...source.vars as Record<string, string>, [key]: value };
      source.vars = vars;
      generated.vars = structuredClone(vars);
      expect(validateDeploymentConfig(source, generated, undefined).tag).toBe(
        "invalid",
      );
    }
    const conflict = configurations();
    conflict.source.secrets_store_secrets = [{
      binding: "PDS_DID",
      store_id: "cccccccccccccccccccccccccccccccc",
      secret_name: "pds-did",
    }];
    conflict.generated.secrets_store_secrets = structuredClone(
      conflict.source.secrets_store_secrets,
    );
    expect(
      validateDeploymentConfig(conflict.source, conflict.generated, undefined)
        .tag,
    ).toBe("invalid");
  });

  it("only exposes fixed preflight diagnostics", () => {
    expect(
      publicPreflightMessage(
        "private\nConfigure production identity variables\nprivate",
      ),
    )
      .toBe("Configure production identity variables");
    expect(publicPreflightMessage("private secret"))
      .toBe("Production deployment preflight failed");
  });

  it("compares raw generated targets and variables to the named source", () => {
    const { source, generated } = configurations();
    expect(generatedTargetsMatchSource(generated, source)).toBe(true);
    for (
      const [key, value] of [
        ["vars", { ENVIRONMENT: "production", PDS_DID: "did:plc:other" }],
        ["d1_databases", [{
          binding: "ALTERAN_DB",
          database_id: "22222222-2222-4222-8222-222222222222",
        }]],
        ["services", [{ binding: "OTHER", service: "other-worker" }]],
      ] as const
    ) {
      const raw = structuredClone(generated);
      raw[key] = value;
      expect(generatedTargetsMatchSource(raw, source)).toBe(false);
    }
  });
});
