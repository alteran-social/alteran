/**
 * Control-flow marker thrown by the auth pipeline when an access token has
 * expired but is otherwise valid. Callers translate this into the
 * `ExpiredToken` XRPC response so clients know to refresh rather than
 * re-authenticate.
 */
export class AuthTokenExpiredError extends Error {
  readonly code = 'ExpiredToken';

  constructor(message: string = 'Token has expired') {
    super(message);
    this.name = 'AuthTokenExpiredError';
  }
}

export function expiredToken(message: string = 'Token has expired'): Response {
  return new Response(
    JSON.stringify({ error: 'ExpiredToken', message }),
    {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    },
  );
}
