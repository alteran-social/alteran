import {
  LtHash,
  type SerializedRecord,
  type SpaceCommit,
  writeRepoStar,
} from "@atproto/space";
import {
  isValidNsid,
  isValidRecordKey,
  SpaceRef,
} from "@atproto/syntax-spaces";
import type { Env } from "../env";
import { isSpaceDid } from "../lib/spaces/space-did";
import { spaceRecordHashElement } from "../lib/spaces/lthash";
import {
  acquireSpaceSnapshot,
  readSpaceSnapshotPage,
  releaseSpaceSnapshot,
} from "../db/space-snapshot";
import { SpaceStorageError } from "../db/space-types";

export type SpaceRepoExport = {
  readonly commit: SpaceCommit;
  readonly body: ReadableStream<Uint8Array>;
};

/** The caller authorizes the repo and authenticates the returned commit. */
export async function streamSpaceRepoArchive(
  env: Env,
  space: string,
  repo: string,
  signal?: AbortSignal,
): Promise<SpaceRepoExport> {
  if (signal?.aborted) throw abortReason(signal);
  if (!isSpaceDid(repo)) {
    throw new SpaceStorageError("RepoNotFound", "Space repo is unavailable");
  }
  const lease = await acquireSpaceSnapshot(env, space, repo);
  const commit: SpaceCommit = {
    ver: 1,
    space: SpaceRef.parse(space).toString(),
    repo,
    rev: lease.rev,
    data: Uint8Array.from(lease.data),
  };
  const returnedCommit: SpaceCommit = {
    ...commit,
    data: Uint8Array.from(commit.data),
  };
  let releasePromise: Promise<void> | undefined;
  const release = () => {
    if (!releasePromise) {
      releasePromise = releaseSpaceSnapshot(env, lease).catch((error) => {
        releasePromise = undefined;
        throw error;
      });
    }
    return releasePromise;
  };
  if (signal?.aborted) {
    try {
      await release();
    } catch (error) {
      reportCleanupFailure(error);
    }
    throw abortReason(signal);
  }

  let stopped = false;
  const ensureActive = () => {
    if (stopped || signal?.aborted) {
      throw signal
        ? abortReason(signal)
        : new DOMException("Stream cancelled", "AbortError");
    }
  };
  async function* records() {
    const hash = new LtHash();
    let cursor: string | null = null;
    for (;;) {
      ensureActive();
      const page = await readSpaceSnapshotPage(env, lease, cursor);
      ensureActive();
      if (page.cursor === null) {
        if (page.records.length !== 0) {
          throw new SpaceStorageError(
            "InvalidRepoState",
            "Space snapshot ended with records",
          );
        }
        if (hash.digest().some((byte, index) => byte !== commit.data[index])) {
          throw new SpaceStorageError(
            "InvalidRepoState",
            "Space snapshot digest does not match",
          );
        }
        await release();
        ensureActive();
        return;
      }
      if (page.cursor === cursor) {
        throw new SpaceStorageError(
          "InvalidRepoState",
          "Space snapshot cursor did not advance",
        );
      }
      for (const record of page.records) {
        ensureActive();
        if (!isValidNsid(record.collection) || !isValidRecordKey(record.rkey)) {
          throw new SpaceStorageError(
            "InvalidRepoState",
            "Invalid Space record path",
          );
        }
        hash.add(
          spaceRecordHashElement(record.collection, record.rkey, record.cid),
        );
        yield {
          collection: record.collection,
          rkey: record.rkey,
          bytes: record.value,
        };
      }
      cursor = page.cursor;
    }
  }
  return makeStream(
    commit,
    returnedCommit,
    records(),
    release,
    signal,
    () => stopped,
    (value) => stopped = value,
  );
}

function makeStream(
  commit: SpaceCommit,
  returnedCommit: SpaceCommit,
  records: AsyncIterable<SerializedRecord>,
  release: () => Promise<void>,
  signal: AbortSignal | undefined,
  isStopped: () => boolean,
  setStopped: (value: boolean) => void,
): SpaceRepoExport {
  const writer = writeRepoStar(commit, records);
  let returnPromise: Promise<unknown> | undefined;
  const stopWriter = () => returnPromise ??= writer.return(undefined);
  let controller: ReadableStreamDefaultController<Uint8Array> | undefined;
  const removeAbort = () => signal?.removeEventListener("abort", onAbort);
  const onAbort = () => {
    if (isStopped()) return;
    setStopped(true);
    removeAbort();
    controller?.error(
      signal
        ? abortReason(signal)
        : new DOMException("Stream aborted", "AbortError"),
    );
    void release().catch(reportCleanupFailure);
    void stopWriter().catch(reportCleanupFailure);
  };
  const body = new ReadableStream<Uint8Array>({
    start(value) {
      controller = value;
    },
    async pull(value) {
      if (isStopped()) return;
      try {
        const chunk = await writer.next();
        if (isStopped()) return;
        if (signal?.aborted) return onAbort();
        if (chunk.done) {
          setStopped(true);
          removeAbort();
          value.close();
        } else {
          value.enqueue(Uint8Array.from(chunk.value));
        }
      } catch (error) {
        if (isStopped()) return;
        setStopped(true);
        removeAbort();
        try {
          await release();
        } catch (cleanupError) {
          reportCleanupFailure(cleanupError);
        }
        value.error(error);
      }
    },
    async cancel() {
      setStopped(true);
      removeAbort();
      const results = await Promise.allSettled([release(), stopWriter()]);
      const failure = results.find((result) => result.status === "rejected");
      if (failure?.status === "rejected") throw failure.reason;
    },
  }, { highWaterMark: 0 });
  signal?.addEventListener("abort", onAbort, { once: true });
  if (signal?.aborted) onAbort();
  return { commit: returnedCommit, body };
}

function abortReason(signal: AbortSignal): unknown {
  return signal.reason ?? new DOMException("Stream aborted", "AbortError");
}

function reportCleanupFailure(error: unknown): void {
  console.error(
    "Space snapshot cleanup failed",
    error instanceof Error ? error.name : "unknown error",
  );
}
