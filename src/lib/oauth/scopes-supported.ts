// Granular permission scopes are parameterised and cannot be enumerated, so
// each supported resource family is advertised by its wildcard form. Only the
// families this server actually enforces are listed.
export const OAUTH_SCOPES_SUPPORTED: readonly string[] = [
  'atproto',
  'transition:email',
  'transition:generic',
  'transition:chat.bsky',
  'repo:*',
  'blob:*/*',
];
