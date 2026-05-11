export async function seed(_db: D1Database, _did: string) {
  // Intentional no-op. The repo_root row is created via UPSERT by bumpRoot()
  // on the first write. Previously this function seeded a placeholder commit
  // CID that wasn't a valid CIDv1, causing the first applyWrites to throw
  // `SyntaxError: Unexpected end of data` when CID.parse decoded it.
}
