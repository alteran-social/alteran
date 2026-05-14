export class RepoWriteError extends Error {
  constructor(
    public readonly error: string,
    message: string,
    public readonly status = 400,
  ) {
    super(message);
  }

  toResponse(): Response {
    return jsonError(this.error, this.message, this.status);
  }
}

export function jsonError(error: string, message?: string, status = 400): Response {
  return new Response(JSON.stringify({
    error,
    ...(message ? { message } : {}),
  }), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

export function invalidSwap(message = 'Invalid swap'): Response {
  return jsonError('InvalidSwap', message, 400);
}

export function handleRepoWriteError(error: unknown): Response {
  if (error instanceof RepoWriteError) return error.toResponse();
  if (isRepoBlobNotFound(error)) {
    return jsonError('BlobNotFound', 'blob not found', 400);
  }
  if (isRepoCommitConflict(error)) {
    return jsonError('InvalidSwap', 'repo head changed', 400);
  }
  throw error;
}

function isRepoCommitConflict(error: unknown): boolean {
  return error instanceof Error && error.name === 'RepoCommitConflictError';
}

function isRepoBlobNotFound(error: unknown): boolean {
  return error instanceof Error && error.name === 'RepoBlobNotFoundError';
}
