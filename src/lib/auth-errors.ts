export class AuthTokenExpiredError extends Error {
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
