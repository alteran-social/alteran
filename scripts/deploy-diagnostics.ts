const PREFLIGHT_MESSAGES = new Set([
  "Unexpected deployment configuration path",
  "Unexpected deployment redirect",
  "Unexpected deployment artifact",
  "Invalid deployment configuration",
  "Conflicting account IDs",
  "Configure the intended Cloudflare account ID",
  "Configure production identity variables",
  "Production build selection does not match",
  "Generated configuration does not match production",
  "Unsupported generated build configuration",
  "Configure explicit production D1, R2 and KV resources",
  "Configure explicit production resource bindings",
  "Configure the production Sequencer binding",
  "Review unsupported Durable Object migration fields",
  "Unsupported production resource binding",
  "Configure private protocol logging settings",
]);

export function publicPreflightMessage(value: unknown): string {
  if (typeof value === "string") {
    const message = value.split(/\r?\n/).map((line) => line.trim()).find((
      line,
    ) => PREFLIGHT_MESSAGES.has(line));
    if (message) return message;
  }
  return "Production deployment preflight failed";
}
