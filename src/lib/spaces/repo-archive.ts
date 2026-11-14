import {
  MAX_RECORD_SIZE,
  readRepoStar,
  serializeRecord,
  type SpaceCommit,
  writeRepoStar,
} from "@atproto/space";
import {
  isValidDid,
  isValidNsid,
  isValidRecordKey,
  isValidTid,
  SpaceRef,
} from "@atproto/syntax-spaces";

export const MAX_SPACE_ARCHIVE_BYTES = 16 * 1024 * 1024;
export const MAX_SPACE_ARCHIVE_RECORDS = 10_000;

export type ArchivedSpaceRecord = {
  readonly collection: string;
  readonly rkey: string;
  readonly cid: string;
  readonly value: Uint8Array;
};

export type SpaceRepoArchive = {
  readonly space: string;
  readonly repo: string;
  readonly rev: string;
  readonly data: Uint8Array;
  readonly records: readonly ArchivedSpaceRecord[];
};

/**
 * Verify a bounded archive's structure and set hash against the expected repo.
 * This does not authenticate the commit or authorize its use. Callers must
 * enforce account and repo authorization independently. Credential-based
 * synchronization also requires verification of the protocol commit MAC;
 * account migration requires an authenticated and authorized import.
 */
export async function readSpaceRepoArchive(
  archive: Uint8Array,
  expected: { readonly space: string; readonly repo: string },
): Promise<SpaceRepoArchive> {
  const { space, repo } = expected;
  if (
    !(archive instanceof Uint8Array) ||
    archive.byteLength > MAX_SPACE_ARCHIVE_BYTES ||
    !validSpace(space) || !isValidDid(repo)
  ) throw new Error("Invalid space archive input");
  const input = Uint8Array.from(archive);
  const reader = await readRepoStar([input]);
  try {
    const { commit } = reader;
    if (
      commit.space !== space || commit.repo !== repo ||
      commit.data.byteLength !== 32
    ) {
      throw new Error("Space archive does not match the expected repo");
    }
    const records: ArchivedSpaceRecord[] = [];
    for await (const record of reader.records) {
      if (records.length >= MAX_SPACE_ARCHIVE_RECORDS) {
        throw new Error("Too many space archive records");
      }
      const encoded = await serializeRecord(
        record.collection,
        record.rkey,
        record.record,
      );
      if (!encoded.cid.equals(record.cid)) {
        throw new Error("Space archive record is not canonical");
      }
      records.push({
        collection: record.collection,
        rkey: record.rkey,
        cid: record.cid.toString(),
        value: Uint8Array.from(encoded.bytes),
      });
    }
    return {
      space: commit.space,
      repo: commit.repo,
      rev: commit.rev,
      data: Uint8Array.from(commit.data),
      records,
    };
  } finally {
    await reader[Symbol.asyncDispose]();
  }
}

/** Build an archive from one consistent snapshot and verify it before release. */
export async function writeSpaceRepoArchive(
  snapshot: SpaceRepoArchive,
): Promise<Uint8Array> {
  if (
    !validSpace(snapshot.space) || !isValidDid(snapshot.repo) ||
    !isValidTid(snapshot.rev) ||
    !(snapshot.data instanceof Uint8Array) || snapshot.data.byteLength !== 32 ||
    !Array.isArray(snapshot.records) ||
    snapshot.records.length > MAX_SPACE_ARCHIVE_RECORDS
  ) {
    throw new Error("Invalid space repo snapshot");
  }
  const commit: SpaceCommit = {
    ver: 1,
    space: SpaceRef.parse(snapshot.space).toString(),
    repo: snapshot.repo,
    rev: snapshot.rev,
    data: Uint8Array.from(snapshot.data),
  };
  let total = 0;
  const records = snapshot.records.map((record) => {
    if (
      !isValidNsid(record.collection) || !isValidRecordKey(record.rkey) ||
      typeof record.cid !== "string" || !(record.value instanceof Uint8Array) ||
      record.value.byteLength > MAX_RECORD_SIZE
    ) throw new Error("Invalid space archive record");
    total += record.value.byteLength;
    if (total > MAX_SPACE_ARCHIVE_BYTES) {
      throw new Error("Space archive is too large");
    }
    return {
      collection: record.collection,
      rkey: record.rkey,
      bytes: Uint8Array.from(record.value),
      cid: record.cid,
    };
  });
  const chunks: Uint8Array[] = [];
  let size = 0;
  for await (const chunk of writeRepoStar(commit, records)) {
    size += chunk.byteLength;
    if (size > MAX_SPACE_ARCHIVE_BYTES) {
      throw new Error("Space archive is too large");
    }
    chunks.push(chunk);
  }
  const result = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.byteLength;
  }
  const checked = await readSpaceRepoArchive(result, {
    space: commit.space,
    repo: commit.repo,
  });
  if (
    checked.records.some((record, index) => record.cid !== records[index].cid)
  ) {
    throw new Error("Space archive record CID does not match its content");
  }
  return result;
}

function validSpace(value: unknown): value is string {
  if (typeof value !== "string") return false;
  try {
    return SpaceRef.parse(value).toString() === value;
  } catch {
    return false;
  }
}
