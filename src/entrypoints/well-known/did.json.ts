import type { APIContext } from "astro";
import { errorMessage } from "../../lib/errors";
import { CACHE_CONFIGS, withCache } from "../../lib/cache";
import { resolveSecret } from "../../lib/secrets";
import { formatMultikey, Secp256k1Keypair } from "@atproto/crypto";
import {
  canonicalPdsOrigin,
  configuredDid,
  configuredHandle,
  validAtprotoHandle,
} from "../../lib/public-host";

export const prerender = false;

export async function GET({ locals, request }: APIContext) {
  const { env } = locals.runtime;

  return withCache(
    request,
    async () => {
      const did = await configuredDid(env);
      const handle = await configuredHandle(env);
      const claimedHandle = validAtprotoHandle(handle);
      const serviceEndpoint = await canonicalPdsOrigin(env);

      let publicKeyMultibase: string | undefined;
      let signingKeyError: string | undefined;
      try {
        const signingKey = await resolveSecret((env as any).REPO_SIGNING_KEY);
        if (!signingKey) {
          signingKeyError = "REPO_SIGNING_KEY not configured";
          console.warn("did.json: REPO_SIGNING_KEY not configured");
        } else {
          const cleaned = signingKey.trim();
          let kp: Secp256k1Keypair;
          if (/^[0-9a-fA-F]{64}$/.test(cleaned)) {
            kp = await Secp256k1Keypair.import(cleaned);
          } else {
            const bin = atob(cleaned.replace(/\s+/g, ""));
            const bytes = new Uint8Array(bin.length);
            for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
            kp = await Secp256k1Keypair.import(bytes);
          }
          publicKeyMultibase = formatMultikey(kp.jwtAlg, kp.publicKeyBytes());
        }
      } catch (error) {
        signingKeyError = `Failed to process REPO_SIGNING_KEY: ${
          errorMessage(error) || error
        }`;
        console.error("did.json: Failed to process REPO_SIGNING_KEY:", error);
      }

      const verificationMethods = publicKeyMultibase
        ? [
          {
            id: `${did}#atproto`,
            type: "Multikey",
            controller: did,
            publicKeyMultibase,
          },
        ]
        : [];

      const didDocument: Record<string, unknown> = {
        "@context": [
          "https://www.w3.org/ns/did/v1",
          "https://w3id.org/security/multikey/v1",
        ],
        id: did,
        alsoKnownAs: claimedHandle ? [`at://${claimedHandle}`] : [],
        verificationMethod: verificationMethods,
        service: [
          {
            id: `${did}#atproto_pds`,
            type: "AtprotoPersonalDataServer",
            serviceEndpoint,
          },
        ],
      };

      // Add debug info if signing key has issues (only visible in dev/debug)
      if (signingKeyError && (env as any).ENVIRONMENT !== "production") {
        didDocument._debug = { signingKeyError };
      }

      return new Response(JSON.stringify(didDocument, null, 2), {
        headers: {
          "Content-Type": "application/json",
        },
      });
    },
    CACHE_CONFIGS.DID_DOCUMENT,
  );
}
