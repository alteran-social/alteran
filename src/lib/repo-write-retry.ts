import { hasSwapCommit } from "./repo-write-input";

export async function retryNoSwapCommit<Result>(
  input: Record<string, unknown>,
  write: () => Promise<Result>,
): Promise<Result> {
  const canRetry = !hasSwapCommit(input);
  const maxAttempts = canRetry ? 3 : 1;
  let lastError: unknown;
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    try {
      return await write();
    } catch (error) {
      lastError = error;
      if (!canRetry || !isRepoCommitConflict(error)) break;
    }
  }
  throw lastError;
}

function isRepoCommitConflict(error: unknown): boolean {
  return error instanceof Error && error.name === "RepoCommitConflictError";
}
