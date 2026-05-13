export const AuthScope = {
  Access: 'com.atproto.access',
  Refresh: 'com.atproto.refresh',
  AppPass: 'com.atproto.appPass',
  AppPassPrivileged: 'com.atproto.appPassPrivileged',
  SignupQueued: 'com.atproto.signupQueued',
  Takendown: 'com.atproto.takendown',
} as const;

export type AuthScope = (typeof AuthScope)[keyof typeof AuthScope];

export type BearerAccessScope =
  | typeof AuthScope.Access
  | typeof AuthScope.AppPass
  | typeof AuthScope.AppPassPrivileged
  | typeof AuthScope.SignupQueued
  | typeof AuthScope.Takendown;

export type AuthAccountStatus =
  | 'unknown'
  | 'active'
  | 'takendown'
  | 'suspended'
  | 'deactivated'
  | 'deleted';

export type AuthAccessKind =
  | 'full'
  | 'app-password'
  | 'app-password-privileged'
  | 'oauth'
  | 'signup-queued'
  | 'takendown';

export type AuthAccessContext = {
  readonly credentialType: 'bearer' | 'oauth-dpop';
  readonly scope: string;
  readonly kind: AuthAccessKind;
  readonly accountStatus: AuthAccountStatus;
  readonly isFullAccess: boolean;
  readonly isPrivileged: boolean;
  readonly isAppPassword: boolean;
  readonly isOAuth: boolean;
  readonly isTakendown: boolean;
  readonly isSignupQueued: boolean;
};

const AUTH_SCOPE_VALUES = new Set<string>(Object.values(AuthScope));
const BEARER_ACCESS_SCOPE_VALUES = new Set<string>([
  AuthScope.Access,
  AuthScope.AppPass,
  AuthScope.AppPassPrivileged,
  AuthScope.SignupQueued,
  AuthScope.Takendown,
]);

export function isAuthScope(scope: unknown): scope is AuthScope {
  return typeof scope === 'string' && AUTH_SCOPE_VALUES.has(scope);
}

export function isBearerAccessScope(scope: unknown): scope is BearerAccessScope {
  return typeof scope === 'string' && BEARER_ACCESS_SCOPE_VALUES.has(scope);
}

export function isOAuthPermissionScope(scope: unknown): scope is string {
  return typeof scope === 'string' && scope.split(/\s+/).includes('atproto');
}

export function bearerAccessContext(
  scope: BearerAccessScope,
  accountStatus: AuthAccountStatus = 'unknown',
): AuthAccessContext {
  switch (scope) {
    case AuthScope.Access:
      return buildAccessContext('bearer', scope, 'full', accountStatus);
    case AuthScope.AppPass:
      return buildAccessContext('bearer', scope, 'app-password', accountStatus);
    case AuthScope.AppPassPrivileged:
      return buildAccessContext('bearer', scope, 'app-password-privileged', accountStatus);
    case AuthScope.SignupQueued:
      return buildAccessContext('bearer', scope, 'signup-queued', accountStatus);
    case AuthScope.Takendown:
      return buildAccessContext('bearer', scope, 'takendown', accountStatus);
  }
}

export function oauthAccessContext(
  scope: string,
  accountStatus: AuthAccountStatus = 'unknown',
): AuthAccessContext {
  return buildAccessContext('oauth-dpop', scope, 'oauth', accountStatus);
}

export function withAccountStatus(
  context: AuthAccessContext,
  accountStatus: AuthAccountStatus,
): AuthAccessContext {
  return buildAccessContext(context.credentialType, context.scope, context.kind, accountStatus);
}

function buildAccessContext(
  credentialType: AuthAccessContext['credentialType'],
  scope: string,
  kind: AuthAccessKind,
  accountStatus: AuthAccountStatus,
): AuthAccessContext {
  return {
    credentialType,
    scope,
    kind,
    accountStatus,
    isFullAccess: kind === 'full',
    isPrivileged: kind === 'full' || kind === 'app-password-privileged',
    isAppPassword: kind === 'app-password' || kind === 'app-password-privileged',
    isOAuth: kind === 'oauth',
    isTakendown: kind === 'takendown' || accountStatus === 'takendown',
    isSignupQueued: kind === 'signup-queued',
  };
}
