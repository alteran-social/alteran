#!/usr/bin/env -S deno run -A
/** Generate PDS credentials and environment-specific Wrangler guidance. */
import { Secp256k1Keypair } from "@atproto/crypto";

function option(name: string, fallback: string): string {
  const index = Deno.args.findIndex((argument) =>
    argument === name || argument.startsWith(`${name}=`)
  );
  if (index < 0) return fallback;
  const argument = Deno.args[index];
  const value = argument.includes("=")
    ? argument.slice(name.length + 1)
    : Deno.args[index + 1];
  if (!value || value.startsWith("--")) throw new Error("Missing option value");
  return value.trim();
}

function randomBase64(length: number): string {
  return btoa(
    String.fromCharCode(...crypto.getRandomValues(new Uint8Array(length))),
  );
}

async function main(): Promise<void> {
  const environment = option("--env", "production");
  if (!["dev", "staging", "production"].includes(environment)) {
    throw new Error("Invalid environment");
  }
  const did = option("--did", "did:web:example.com");
  const handle = option("--handle", "user.example.com");
  const hostname = option("--hostname", handle);
  const password = option("--password", randomBase64(24));
  const sessionSecret = randomBase64(32);
  const keypair = await Secp256k1Keypair.create({ exportable: true });
  const signingKey = Array.from(await keypair.export()).map((byte) =>
    byte.toString(16).padStart(2, "0")
  ).join("");
  const writeDevVars = Deno.args.includes("--write-dev-vars");
  if (writeDevVars && environment !== "dev") {
    throw new Error("Local variables require the dev environment");
  }

  console.log("The following output contains credentials. Keep it private.");
  console.log(
    "Use these credentials for initial setup; do not replace an existing repository signing key without a reviewed rotation procedure.",
  );
  console.log(
    `Configure PDS_DID, PDS_HANDLE and PDS_HOSTNAME in the ${environment} vars of wrangler.jsonc.`,
  );
  console.log(
    "Confirm that same-name secrets do not conflict with those vars.",
  );
  console.log(`PDS_DID=${did}\nPDS_HANDLE=${handle}\nPDS_HOSTNAME=${hostname}`);
  console.log(
    "Set these secrets after verifying the intended Cloudflare account:",
  );
  for (
    const name of ["USER_PASSWORD", "SESSION_JWT_SECRET", "REPO_SIGNING_KEY"]
  ) {
    console.log(
      `deno run -A npm:wrangler secret put ${name} --env ${environment}`,
    );
  }
  console.log(
    `USER_PASSWORD=${password}\nSESSION_JWT_SECRET=${sessionSecret}\nREPO_SIGNING_KEY=${signingKey}`,
  );
  console.log(
    "SESSION_JWT_SECRET can instead be generated and stored in D1 at runtime.",
  );

  if (writeDevVars) {
    const target = ".dev.vars";
    let existing: Deno.FileInfo | undefined;
    try {
      existing = await Deno.lstat(target);
    } catch (error) {
      if (!(error instanceof Deno.errors.NotFound)) throw error;
    }
    if (existing?.isSymlink || (existing && !existing.isFile)) {
      throw new Error("Invalid local variables file");
    }
    if (existing && !Deno.args.includes("--force")) {
      throw new Error("Local variables file already exists");
    }
    const content = [
      `PDS_DID=${did}`,
      `PDS_HANDLE=${handle}`,
      `PDS_HOSTNAME=${hostname}`,
      `USER_PASSWORD=${password}`,
      `SESSION_JWT_SECRET=${sessionSecret}`,
      `REPO_SIGNING_KEY=${signingKey}`,
      "PDS_CORS_ORIGIN=*",
      "",
    ].join("\n");
    await Deno.writeTextFile(target, content, {
      mode: 0o600,
      createNew: !existing,
    });
    await Deno.chmod(target, 0o600);
    console.log("Wrote private local development variables");
  }

  const location = environment === "dev" ? "--local" : "--remote";
  console.log(
    `After verifying the account and database, apply migrations: deno run -A npm:wrangler d1 migrations apply ALTERAN_DB --env ${environment} ${location}`,
  );
  if (environment === "production") {
    console.log(
      "Deploy with deno task deploy after completing docs/DEPLOYMENT.md.",
    );
  } else if (environment === "staging") {
    console.log(
      "Build with CLOUDFLARE_ENV=staging deno task build and review docs/DEPLOYMENT.md.",
    );
  } else console.log("Start development with deno task dev.");
}

if (import.meta.main) {
  try {
    await main();
  } catch {
    console.error(
      "Could not prepare credentials; check the environment and local file options",
    );
    Deno.exit(1);
  }
}
