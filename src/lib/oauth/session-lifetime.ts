// A public client cannot prove who it is when it refreshes, so its session
// gets a fixed end instead of sliding forward on every refresh. Two weeks is
// the reference implementation's SESSION_LIFETIME for unauthenticated clients.
const PUBLIC_CLIENT_SESSION_SECONDS = 14 * 24 * 60 * 60;

export type OAuthSessionLifetimeEvent =
  | { readonly tag: 'created'; readonly now: number }
  | { readonly tag: 'refreshed'; readonly currentExpiresAt: number };

export function oauthSessionExpiresAt(
  clientAuthMethod: string,
  refreshTokenExpiresAt: number,
  event: OAuthSessionLifetimeEvent,
): number {
  // Read from storage as a plain string: anything that is not a proven
  // confidential client is treated as public.
  if (clientAuthMethod === 'private_key_jwt') return refreshTokenExpiresAt;
  const ceiling = event.tag === 'created'
    ? event.now + PUBLIC_CLIENT_SESSION_SECONDS
    : event.currentExpiresAt;
  return Math.min(refreshTokenExpiresAt, ceiling);
}
