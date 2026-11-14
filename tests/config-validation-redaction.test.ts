import { describe, it } from "@std/testing/bdd";
import { expect } from "@std/expect";
import type { Env } from "../src/env";
import {
  logConfigValidation,
  validateConfig,
  validateConfigOrThrow,
} from "../src/lib/config";

function capture(run: () => void): string[] {
  const logs: string[] = [];
  const original = {
    log: console.log,
    warn: console.warn,
    error: console.error,
  };
  const collect = (...values: unknown[]) =>
    logs.push(values.map(String).join(" "));
  try {
    console.log = collect;
    console.warn = collect;
    console.error = collect;
    run();
    return logs;
  } finally {
    console.log = original.log;
    console.warn = original.warn;
    console.error = original.error;
  }
}

describe("configuration validation diagnostics", () => {
  it("reports setting names without returning configured values in warnings or logs", () => {
    const marker = `config-marker-${crypto.randomUUID()}`;
    const env = {
      PDS_DID: marker,
      PDS_HANDLE: `https://${marker}`,
      PDS_MAX_BLOB_SIZE: marker,
      PDS_MAX_JSON_BYTES: marker,
      PDS_RATE_LIMIT_PER_MIN: marker,
      PDS_CORS_ORIGIN: marker,
      PDS_BSKY_APP_VIEW_URL: marker,
      PDS_BSKY_APP_VIEW_DID: marker,
      PDS_BSKY_APP_VIEW_CDN_URL_PATTERN: marker,
      PDS_BSKY_CHAT_URL: marker,
      PDS_BSKY_CHAT_DID: marker,
      PDS_OZONE_URL: marker,
      PDS_OZONE_DID: marker,
      ENVIRONMENT: marker,
      REPO_SIGNING_KEY: marker,
    } as unknown as Env;
    const result = validateConfig(env);
    expect(result.valid).toBe(true);
    expect(result.warnings.every((warning) => !warning.includes(marker))).toBe(
      true,
    );
    for (
      const name of [
        "PDS_DID",
        "PDS_HANDLE",
        "PDS_MAX_BLOB_SIZE",
        "PDS_MAX_JSON_BYTES",
        "PDS_RATE_LIMIT_PER_MIN",
      ]
    ) {
      expect(result.warnings.some((warning) => warning.includes(name))).toBe(
        true,
      );
    }
    const logs = capture(() => validateConfigOrThrow(env));
    expect(logs.some((line) => line.includes(marker))).toBe(false);
    for (
      const name of [
        "PDS_DID",
        "PDS_HANDLE",
        "PDS_MAX_BLOB_SIZE",
        "PDS_MAX_JSON_BYTES",
        "PDS_RATE_LIMIT_PER_MIN",
      ]
    ) {
      expect(logs.some((line) => line.includes(name))).toBe(true);
    }
  });

  it("keeps missing-setting errors useful and sanitized", () => {
    const marker = `config-marker-${crypto.randomUUID()}`;
    const env = {
      PDS_HANDLE: `https://${marker}`,
      PDS_MAX_JSON_BYTES: marker,
      ENVIRONMENT: marker,
    } as unknown as Env;
    const result = validateConfig(env);
    expect(result.valid).toBe(false);
    let thrown: unknown;
    const logs = capture(() => {
      logConfigValidation(result);
      try {
        validateConfigOrThrow(env);
      } catch (error) {
        thrown = error;
      }
    });
    expect(thrown instanceof Error && !thrown.message.includes(marker)).toBe(
      true,
    );
    expect(logs.some((line) => line.includes(marker))).toBe(false);
    for (const name of ["PDS_DID", "PDS_HANDLE", "PDS_MAX_JSON_BYTES"]) {
      expect(logs.some((line) => line.includes(name))).toBe(true);
    }
  });

  it("does not coerce invalid numeric objects while validating or logging", () => {
    const marker = `config-marker-${crypto.randomUUID()}`;
    const value = {
      [Symbol.toPrimitive]() {
        throw new Error(marker);
      },
    };
    const env = {
      PDS_DID: "did:example:test",
      PDS_HANDLE: "test.example",
      PDS_MAX_BLOB_SIZE: value,
      PDS_MAX_JSON_BYTES: value,
      PDS_RATE_LIMIT_PER_MIN: value,
    } as unknown as Env;
    const result = validateConfig(env);
    expect(result.valid).toBe(true);
    expect(
      result.warnings.some((warning) => warning.includes("PDS_MAX_BLOB_SIZE")),
    ).toBe(true);
    const logs = capture(() => validateConfigOrThrow(env));
    expect(logs.some((line) => line.includes(marker))).toBe(false);
  });
});
