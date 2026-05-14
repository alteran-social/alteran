export const MAX_COMMIT_OPS = 200;
export const MAX_COMMIT_BLOCKS_BYTES = 2_000_000;
export const MAX_RECORD_BLOCK_BYTES = 1_000_000;

export class RepoWriteLimitError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RepoWriteLimitError';
  }
}

export function assertRecordBlockSize(byteLength: number): void {
  if (byteLength > MAX_RECORD_BLOCK_BYTES) {
    throw new RepoWriteLimitError(
      `record block exceeds ${MAX_RECORD_BLOCK_BYTES} byte commit event limit`,
    );
  }
}

export function assertCommitEventLimits(
  opsLength: number,
  blocksByteLength: number,
): void {
  if (opsLength > MAX_COMMIT_OPS) {
    throw new RepoWriteLimitError(
      `commit event exceeds ${MAX_COMMIT_OPS} record operation limit`,
    );
  }
  if (blocksByteLength > MAX_COMMIT_BLOCKS_BYTES) {
    throw new RepoWriteLimitError(
      `commit blocks exceed ${MAX_COMMIT_BLOCKS_BYTES} byte commit event limit`,
    );
  }
}
