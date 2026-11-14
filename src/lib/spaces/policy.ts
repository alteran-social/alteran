import { isAtprotoDidRefAbsolute } from "@atproto/did";
import { isLexiconUri } from "./lexicon-uri";
import { copyPlainArray, copyPlainRecordWithExtensions } from "./plain-values";

export type PersonalSpacePolicy = {
  readonly $type: "com.atproto.personalspace.policy";
};

export type MemberSpacePolicy = {
  readonly $type: "com.atproto.memberspace.policy";
  readonly publicRead: boolean;
  readonly publicWrite: boolean;
  readonly allowedApps?: readonly string[];
  readonly publishPolicy: boolean;
  readonly publishMembers: boolean;
};

export type ManagedSpacePolicy = {
  readonly $type: "com.atproto.managedspace.policy";
  readonly managingApp: string;
  readonly publishPolicy: boolean;
};

export type SpacePolicy =
  | PersonalSpacePolicy
  | MemberSpacePolicy
  | ManagedSpacePolicy;

export type SpacePolicyParseResult =
  | { readonly tag: "valid"; readonly policy: SpacePolicy }
  | { readonly tag: "invalid" | "unsupported" };

/** Parse the baseline open union and discard unrecognized extension fields. */
export function parseSpacePolicy(value: unknown): SpacePolicyParseResult {
  const fields = copyPlainRecordWithExtensions(value, 64);
  if (!fields || typeof fields.$type !== "string") return { tag: "invalid" };
  if (fields.$type === "com.atproto.personalspace.policy") {
    return { tag: "valid", policy: Object.freeze({ $type: fields.$type }) };
  }
  if (fields.$type === "com.atproto.memberspace.policy") {
    const publicRead = optionalBoolean(fields.publicRead);
    const publicWrite = optionalBoolean(fields.publicWrite);
    const publishPolicy = optionalBoolean(fields.publishPolicy);
    const publishMembers = optionalBoolean(fields.publishMembers);
    if (
      publicRead === null || publicWrite === null || publishPolicy === null ||
      publishMembers === null
    ) {
      return { tag: "invalid" };
    }
    let allowedApps: readonly string[] | undefined;
    if (fields.allowedApps !== undefined) {
      const apps = copyPlainArray(fields.allowedApps, 256);
      if (
        !apps ||
        !apps.every((app) => isLexiconUri(app))
      ) return { tag: "invalid" };
      allowedApps = Object.freeze(apps as string[]);
    }
    return {
      tag: "valid",
      policy: Object.freeze({
        $type: fields.$type,
        publicRead,
        publicWrite,
        ...(allowedApps === undefined ? {} : { allowedApps }),
        publishPolicy,
        publishMembers,
      }),
    };
  }
  if (fields.$type === "com.atproto.managedspace.policy") {
    const publishPolicy = optionalBoolean(fields.publishPolicy);
    if (
      typeof fields.managingApp !== "string" ||
      fields.managingApp.length > 2048 ||
      !isAtprotoDidRefAbsolute(fields.managingApp) || publishPolicy === null
    ) return { tag: "invalid" };
    return {
      tag: "valid",
      policy: Object.freeze({
        $type: fields.$type,
        managingApp: fields.managingApp,
        publishPolicy,
      }),
    };
  }
  return { tag: "unsupported" };
}

function optionalBoolean(value: unknown): boolean | null {
  return value === undefined
    ? false
    : typeof value === "boolean"
    ? value
    : null;
}
