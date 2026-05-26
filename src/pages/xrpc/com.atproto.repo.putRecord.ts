import type { APIContext } from "astro";
import { errorCode } from "../../lib/errors";
import {
  dpopResourceUnauthorized,
  handleResourceAuthError,
  insufficientScopeResponse,
  verifyResourceRequestHybrid,
} from "../../lib/oauth/resource";
import { canWriteRepo } from "../../lib/auth-scope";
import { checkRate } from "../../lib/ratelimit";
import { readJsonBounded } from "../../lib/util";
import { notifySequencer } from "../../lib/sequencer";
import {
  deleteUnreferencedBlobKeys,
  isAccountActive,
  sweepEligibleUnreferencedBlobKeys,
} from "../../db/dal";
import {
  assertRepoWriteInput,
  putRecordAuthorizations,
} from "../../lib/repo-write-input";
import { retryNoSwapCommit } from "../../lib/repo-write-retry";
import {
  handleRepoWriteError,
  jsonError,
  preparePutRecord,
  RepoWriteError,
} from "../../lib/repo-write-validation";

export const prerender = false;

export async function POST({ locals, request }: APIContext) {
  const { env } = locals;
  const ctx = locals.cfContext;
  let auth: NonNullable<
    Awaited<ReturnType<typeof verifyResourceRequestHybrid>>
  >;
  try {
    const verified = await verifyResourceRequestHybrid(env, request);
    if (!verified) return dpopResourceUnauthorized(env);
    auth = verified;
  } catch (error) {
    const handled = await handleResourceAuthError(env, error);
    if (handled) return handled;
    throw error;
  }

  let body: unknown;
  try {
    body = await readJsonBounded(env, request);
  } catch (error) {
    const rateLimitResponse = await checkRate(env, request, "writes", {
      key: auth.did,
    });
    if (rateLimitResponse) return rateLimitResponse;
    if (errorCode(error) === "PayloadTooLarge") {
      return jsonError("PayloadTooLarge", undefined, 413);
    }
    return jsonError("BadRequest");
  }

  let writeRateCharged = false;
  try {
    const input = assertRepoWriteInput("com.atproto.repo.putRecord", body);
    for (const write of putRecordAuthorizations(input)) {
      if (!canWriteRepo(auth.access, write.collection, write.action)) {
        return insufficientScopeResponse();
      }
    }

    const rateLimitResponse = await checkRate(env, request, "writes", {
      key: auth.did,
    });
    writeRateCharged = true;
    if (rateLimitResponse) return rateLimitResponse;

    if (!(await isAccountActive(env, auth.did))) {
      return jsonError(
        "AccountDeactivated",
        "Account is deactivated. Activate it before making changes.",
        403,
      );
    }

    const { prepared, result } = await retryNoSwapCommit(input, async () => {
      const prepared = await preparePutRecord(env, auth, input);
      const { write, repo } = prepared;
      const result = await repo.putRecord(
        write.collection,
        write.rkey,
        write.record,
        write.blobKeys,
        prepared.expectedCommitCid,
      );
      return { prepared, result };
    });
    if (
      result.commitCid && result.rev && result.commitData && result.sig &&
      result.blocks
    ) {
      await notifySequencer(env, {
        did: prepared.did,
        commitCid: result.commitCid,
        rev: result.rev,
        data: result.commitData,
        sig: result.sig,
        ops: result.ops,
        blocks: result.blocks,
      });
      await deleteUnreferencedBlobKeys(env, result.dereferencedBlobKeys).catch(
        (error) => {
          console.warn(
            "[putRecord] Failed to clean dereferenced blobs:",
            error,
          );
        },
      );
      ctx?.waitUntil(
        sweepEligibleUnreferencedBlobKeys(env).catch((error) => {
          console.warn(
            "[putRecord] Failed to sweep dereferenced blobs:",
            error,
          );
        }),
      );
    }

    return new Response(
      JSON.stringify({
        uri: result.uri,
        cid: result.cid,
        ...(result.commitCid && result.rev
          ? {
            commit: {
              cid: result.commitCid,
              rev: result.rev,
            },
          }
          : {}),
        validationStatus: prepared.write.validationStatus,
      }),
      {
        headers: { "Content-Type": "application/json" },
      },
    );
  } catch (error) {
    if (!writeRateCharged && error instanceof RepoWriteError) {
      const rateLimitResponse = await checkRate(env, request, "writes", {
        key: auth.did,
      });
      if (rateLimitResponse) return rateLimitResponse;
    }
    return handleRepoWriteError(error);
  }
}
