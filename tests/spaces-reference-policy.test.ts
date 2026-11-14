import { P256Keypair } from "@atproto/crypto-spaces";
import { isValidDid } from "@atproto/syntax-spaces";
import { expect } from "@std/expect";
import {
  decideSpaceAccountAccess,
  decideSpaceClientAccess,
} from "../src/lib/spaces/policy-access";

const configPath = Deno.env.get("ALTERAN_REFERENCE_INTEROP_CONFIG");

Deno.test({
  name: "reference PDS: memberspace anonymous and client policy decisions",
  ignore: !configPath,
  async fn() {
    if (!configPath) throw new Error("Reference configuration is required");
    const config: unknown = JSON.parse(await Deno.readTextFile(configPath));
    if (!config || typeof config !== "object") {
      throw new Error("Invalid reference configuration");
    }
    const fields = config as Record<string, unknown>;
    if (
      typeof fields.pds !== "string" || typeof fields.accessJwt !== "string" ||
      !fields.accessJwt || !isValidDid(fields.did)
    ) throw new Error("Invalid reference account");
    const origin = new URL(fields.pds);
    if (
      origin.protocol !== "http:" ||
      !["127.0.0.1", "localhost", "[::1]"].includes(origin.hostname) ||
      origin.username || origin.password || origin.pathname !== "/" ||
      origin.search || origin.hash
    ) {
      throw new Error("Reference test requires a loopback HTTP origin");
    }
    const authorization = `Bearer ${fields.accessJwt}`;
    const skey = `policy-${crypto.randomUUID()}`;
    const space = `at://${fields.did}/space/com.example.forum/${skey}`;
    const credentialKey = (await P256Keypair.create()).did();
    const request = (method: string, body: unknown, authenticated = false) =>
      fetch(
        `${origin.origin}/xrpc/${method}`,
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            ...(authenticated ? { authorization } : {}),
          },
          body: JSON.stringify(body),
          signal: AbortSignal.timeout(10_000),
          redirect: "manual",
        },
      );
    const update = async (policy: unknown) => {
      const response = await request("com.atproto.space.updateSpace", {
        space,
        policy,
      }, true);
      if (!response.ok) {
        throw new Error(
          `Reference policy update failed: HTTP ${response.status}`,
        );
      }
      await response.body?.cancel();
    };
    const authorize = () =>
      request("com.atproto.space.authorizeSpaceSync", { space, credentialKey });
    const membership = { tag: "not-checked" } as const;
    let created = false;
    try {
      const initialPolicy = { $type: "com.atproto.memberspace.policy" };
      const creation = await request("com.atproto.space.createSpace", {
        spaceType: "com.example.forum",
        skey,
        policy: initialPolicy,
      }, true);
      if (!creation.ok) {
        throw new Error(
          `Reference Space creation failed: HTTP ${creation.status}`,
        );
      }
      created = true;
      await creation.body?.cancel();

      const initial = await authorize();
      expect(initial.status).toBe(400);
      expect((await initial.json()).error).toBe("SpaceNotFound");
      expect(
        decideSpaceAccountAccess(initialPolicy, {
          space,
          repo: null,
          action: "read",
          membership,
        }).tag,
      )
        .toBe("denied");

      const publicPolicy = { ...initialPolicy, publicRead: true };
      await update(publicPolicy);
      const permitted = await authorize();
      expect(permitted.status).toBe(200);
      await permitted.body?.cancel();
      expect(
        decideSpaceAccountAccess(publicPolicy, {
          space,
          repo: null,
          action: "read",
          membership,
        }).tag,
      )
        .toBe("allowed");

      const restricted = { ...publicPolicy, allowedApps: [] };
      await update(restricted);
      const rejected = await authorize();
      expect(rejected.status).toBe(400);
      expect((await rejected.json()).error).toBe("AppNotAuthorized");
      expect(decideSpaceClientAccess(restricted, { tag: "absent" }).tag).toBe(
        "denied",
      );
    } finally {
      if (created) {
        const response = await request("com.atproto.space.deleteSpace", {
          space,
        }, true);
        await response.body?.cancel();
        if (!response.ok) {
          throw new Error(
            `Reference Space cleanup failed: HTTP ${response.status}`,
          );
        }
      }
    }
  },
});
