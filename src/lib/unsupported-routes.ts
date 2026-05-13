const SINGLE_USER_UNSUPPORTED_ROUTES: ReadonlySet<string> = new Set([
  'com.atproto.server.createAccount',
  'com.atproto.server.reserveSigningKey',
  'com.atproto.server.createInviteCode',
  'com.atproto.server.createInviteCodes',
  'com.atproto.server.getAccountInviteCodes',
  'com.atproto.temp.addReservedHandle',
  'com.atproto.temp.checkHandleAvailability',
  'com.atproto.temp.checkSignupQueue',
  'com.atproto.temp.requestPhoneVerification',
  'com.atproto.temp.revokeAccountCredentials',
]);

const SINGLE_USER_UNSUPPORTED_PREFIXES = ['com.atproto.admin.'];

export function isSingleUserUnsupportedRoute(nsid: string): boolean {
  return SINGLE_USER_UNSUPPORTED_ROUTES.has(nsid) ||
    SINGLE_USER_UNSUPPORTED_PREFIXES.some((prefix) => nsid.startsWith(prefix));
}

export function unsupportedSingleUserRouteResponse(nsid: string): Response {
  return new Response(
    JSON.stringify({
      error: 'NotImplemented',
      message: `${nsid} is intentionally unsupported by Alteran single-user PDS`,
    }),
    {
      status: 501,
      headers: { 'Content-Type': 'application/json' },
    },
  );
}
