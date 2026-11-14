/** Shared worst-case bounds for one trusted Space Lexicon resolution. */
export const SPACE_LEXICON_LIMITS = Object.freeze({
  attempts: 2,
  declarationsPerRequest: 2,
  dnsCallsPerAttempt: 2,
  httpCallsPerAttempt: 5,
  dnsResponseBytes: 65_535,
  jsonResponseBytes: 64 * 1024,
  proofResponseBytes: 4 * 1024 * 1024,
});
