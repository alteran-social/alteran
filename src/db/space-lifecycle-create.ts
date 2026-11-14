import type { Env } from "../env";
import { parseSpacePolicy } from "../lib/spaces/policy";
import { SpaceStorageError } from "./space-types";
import {
  assertPersonalAuthority,
  invalidLifecycleRequest,
  validLifecycleNonce,
} from "./space-lifecycle-types";

/** Create a personal Space and its explicit policy as one primary-D1 transaction. */
export async function createPersonalSpace(
  env: Env,
  spaceRef: string,
  policy: unknown,
  nonce: string,
): Promise<void> {
  if (!validLifecycleNonce(nonce)) throw invalidLifecycleRequest();
  const parsed = parseSpacePolicy(policy);
  if (
    parsed.tag !== "valid" ||
    parsed.policy.$type !== "com.atproto.personalspace.policy"
  ) {
    throw new SpaceStorageError(
      "UnsupportedPolicy",
      "Only personal Space creation is available",
    );
  }
  const ref = await assertPersonalAuthority(env, spaceRef);
  if (
    await hasCreationReceipt(
      env,
      ref.ref,
      ref.authorityDid,
      ref.spaceType,
      ref.skey,
      nonce,
    )
  ) return;
  const createdAt = Date.now();
  try {
    await env.ALTERAN_DB.batch([
      env.ALTERAN_DB.prepare(`INSERT INTO space_personal_creation_attempt
        (nonce, space_ref, authority_did, space_type, skey, created_at)
        SELECT ?, ?, ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM space WHERE space_ref = ?)
          AND NOT EXISTS (SELECT 1 FROM space_personal_policy WHERE creation_nonce = ?)`)
        .bind(
          nonce,
          ref.ref,
          ref.authorityDid,
          ref.spaceType,
          ref.skey,
          createdAt,
          ref.ref,
          nonce,
        ),
      env.ALTERAN_DB.prepare(
        `INSERT OR IGNORE INTO space (space_ref, authority_did, space_type, skey, created_at)
        SELECT space_ref, authority_did, space_type, skey, created_at FROM space_personal_creation_attempt
        WHERE nonce = ? AND space_ref = ? AND authority_did = ?`,
      ).bind(nonce, ref.ref, ref.authorityDid),
      env.ALTERAN_DB.prepare(`INSERT INTO space_personal_policy
        (space_ref, authority_did, policy_type, creation_nonce, notification_state, created_at)
        SELECT space_ref, authority_did, 'com.atproto.personalspace.policy', nonce, 'none', created_at
        FROM space_personal_creation_attempt WHERE nonce = ? AND space_ref = ? AND authority_did = ?`)
        .bind(nonce, ref.ref, ref.authorityDid),
      env.ALTERAN_DB.prepare(`SELECT CASE WHEN EXISTS (
        SELECT 1 FROM space s JOIN space_personal_policy p ON p.space_ref = s.space_ref AND p.authority_did = s.authority_did
        WHERE s.space_ref = ? AND s.authority_did = ? AND s.space_type = ? AND s.skey = ? AND s.deleted_at IS NULL
          AND p.creation_nonce = ? AND p.policy_type = 'com.atproto.personalspace.policy' AND p.notification_state = 'none'
      ) THEN 1 ELSE json('{') END AS valid`).bind(
        ref.ref,
        ref.authorityDid,
        ref.spaceType,
        ref.skey,
        nonce,
      ),
      env.ALTERAN_DB.prepare(
        "DELETE FROM space_personal_creation_attempt WHERE nonce = ? AND space_ref = ?",
      )
        .bind(nonce, ref.ref),
      env.ALTERAN_DB.prepare(`SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM space_personal_creation_attempt WHERE nonce = ?
      ) THEN 1 ELSE json('{') END AS valid`).bind(nonce),
    ]);
  } catch (error) {
    if (
      await hasCreationReceipt(
        env,
        ref.ref,
        ref.authorityDid,
        ref.spaceType,
        ref.skey,
        nonce,
      )
    ) return;
    const existing = await env.ALTERAN_DB.prepare(
      "SELECT 1 AS present FROM space WHERE space_ref = ?",
    )
      .bind(ref.ref).first<{ present: number }>();
    if (existing) {
      throw new SpaceStorageError(
        "SpaceAlreadyExists",
        "Space already exists or was deleted",
      );
    }
    throw error;
  }
}

async function hasCreationReceipt(
  env: Env,
  spaceRef: string,
  authorityDid: string,
  spaceType: string,
  skey: string,
  nonce: string,
): Promise<boolean> {
  const receipt = await env.ALTERAN_DB.prepare(
    `SELECT 1 AS present FROM space s JOIN space_personal_policy p
    ON p.space_ref = s.space_ref AND p.authority_did = s.authority_did
    WHERE s.space_ref = ? AND s.authority_did = ? AND s.space_type = ? AND s.skey = ? AND s.deleted_at IS NULL
      AND p.created_at = s.created_at
      AND p.creation_nonce = ? AND p.policy_type = 'com.atproto.personalspace.policy' AND p.notification_state = 'none'`,
  )
    .bind(spaceRef, authorityDid, spaceType, skey, nonce).first<
    { present: number }
  >();
  return receipt?.present === 1;
}
