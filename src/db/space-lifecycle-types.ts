import type { Env } from "../env";
import { copyPlainRecord } from "../lib/spaces/plain-values";
import { assertLocalSpaceRepo, parseSpaceRef } from "./space-ref";
import { SpaceStorageError } from "./space-types";

export type PersonalDeletionHandle = {
  readonly spaceRef: string;
  readonly authorityDid: string;
  readonly nonce: string;
};
export type PersonalDeletionPhase = "records" | "versions" | "ops" | "done";
export type PersonalDeletionStatus = {
  readonly status: "deleting" | "complete";
  readonly phase: PersonalDeletionPhase;
  readonly sequence: number;
  readonly lastStepNonce: string | null;
  readonly lastStepPhase: Exclude<PersonalDeletionPhase, "done"> | null;
  readonly lastStepCount: number;
};
export type PersonalDeletionStep =
  | {
    readonly tag: "progress" | "complete";
    readonly status: PersonalDeletionStatus;
  }
  | { readonly tag: "conflict" | "unavailable" };

export function validLifecycleNonce(value: unknown): value is string {
  return typeof value === "string" &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
      .test(value);
}

export function captureDeletionHandle(
  value: PersonalDeletionHandle,
): PersonalDeletionHandle {
  const fields = copyPlainRecord(value, ["spaceRef", "authorityDid", "nonce"]);
  if (
    !fields || typeof fields.spaceRef !== "string" ||
    typeof fields.authorityDid !== "string" ||
    !validLifecycleNonce(fields.nonce)
  ) throw invalidLifecycleRequest();
  const ref = parseSpaceRef(fields.spaceRef);
  if (ref.authorityDid !== fields.authorityDid) throw invalidLifecycleRequest();
  return {
    spaceRef: fields.spaceRef,
    authorityDid: fields.authorityDid,
    nonce: fields.nonce,
  };
}

export async function assertPersonalAuthority(
  env: Env,
  spaceRef: string,
): Promise<ReturnType<typeof parseSpaceRef>> {
  const ref = parseSpaceRef(spaceRef);
  await assertLocalSpaceRepo(env, ref.authorityDid);
  return ref;
}

export function invalidLifecycleRequest(): SpaceStorageError {
  return new SpaceStorageError(
    "InvalidRequest",
    "Invalid personal Space lifecycle request",
  );
}
