import { lexiconSpaceSchema } from "@atproto/lex-document";
import { isValidNsid, isValidTid } from "@atproto/syntax-spaces";
import { copyPlainArray, copyPlainRecord } from "./plain-values";
import { parseCanonicalRepoCid } from "./repo-cid";
import { isSpaceDid } from "./space-did";

export type SpaceDeclarationEvidence = {
  readonly spaceType: string;
  readonly publisherDid: string;
  readonly recordCid: string;
  readonly headCid: string;
  readonly revision: string;
  readonly observedAt: number;
  readonly key: string;
  readonly title?: string;
  readonly collections: readonly string[];
};

/** Copy resolver evidence; structural validation does not establish provenance. */
export function copySpaceDeclarationEvidence(
  value: unknown,
): SpaceDeclarationEvidence | null {
  const required = [
    "spaceType",
    "publisherDid",
    "recordCid",
    "headCid",
    "revision",
    "observedAt",
    "key",
    "collections",
  ];
  const fields = copyPlainRecord(value, required) ??
    copyPlainRecord(value, [...required, "title"]);
  const collections = fields && copyPlainArray(fields.collections, 128);
  if (
    !fields || typeof fields.spaceType !== "string" ||
    !isValidNsid(fields.spaceType) ||
    !isSpaceDid(fields.publisherDid) || !canonicalCid(fields.recordCid) ||
    !canonicalCid(fields.headCid) ||
    typeof fields.revision !== "string" || !isValidTid(fields.revision) ||
    typeof fields.observedAt !== "number" ||
    !Number.isSafeInteger(fields.observedAt) ||
    fields.observedAt < 0 || fields.observedAt > Date.now() ||
    typeof fields.key !== "string" || fields.key.length > 520 ||
    (fields.title !== undefined &&
      (typeof fields.title !== "string" || fields.title.length > 64)) ||
    !collections ||
    !collections.every((item) =>
      typeof item === "string" && isValidNsid(item)
    ) ||
    !lexiconSpaceSchema.safeParse({
      type: "space",
      key: fields.key,
      collections,
      ...(fields.title === undefined ? {} : { title: fields.title }),
    }).success
  ) return null;
  return Object.freeze({
    spaceType: fields.spaceType,
    publisherDid: fields.publisherDid,
    recordCid: fields.recordCid,
    headCid: fields.headCid,
    revision: fields.revision,
    observedAt: fields.observedAt,
    key: fields.key,
    ...(fields.title === undefined ? {} : { title: fields.title }),
    collections: Object.freeze([...new Set(collections as string[])]),
  });
}

function canonicalCid(value: unknown): value is string {
  const cid = parseCanonicalRepoCid(value);
  return typeof value === "string" && cid !== null && cid.toString() === value;
}
