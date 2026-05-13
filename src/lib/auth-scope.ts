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
const OAUTH_PROFILE_SCOPE = 'atproto';
const OAUTH_TRANSITION_GENERIC = 'transition:generic';
const OAUTH_TRANSITION_CHAT = 'transition:chat.bsky';
const OAUTH_TRANSITION_EMAIL = 'transition:email';
const OAUTH_TRANSITION_SCOPES = new Set([
  OAUTH_TRANSITION_GENERIC,
  OAUTH_TRANSITION_CHAT,
  OAUTH_TRANSITION_EMAIL,
]);
const REPO_ACTIONS = new Set(['create', 'update', 'delete']);
const ACCOUNT_ACTIONS = new Set(['read', 'manage']);
const OAUTH_RESOURCE_TYPES = new Set(['repo', 'rpc', 'blob', 'identity', 'account', 'include']);
const TRANSITION_GENERIC_BLOCKED_RPC = new Set([
  'chat.bsky.actor.deleteAccount',
  'com.atproto.admin.sendEmail',
  'com.atproto.identity.requestPlcOperationSignature',
  'com.atproto.identity.signPlcOperation',
  'com.atproto.identity.updateHandle',
  'com.atproto.server.activateAccount',
  'com.atproto.server.confirmEmail',
  'com.atproto.server.createAccount',
  'com.atproto.server.createAppPassword',
  'com.atproto.server.deactivateAccount',
  'com.atproto.server.getAccountInviteCodes',
  'com.atproto.server.listAppPasswords',
  'com.atproto.server.requestAccountDelete',
  'com.atproto.server.requestEmailConfirmation',
  'com.atproto.server.requestEmailUpdate',
  'com.atproto.server.revokeAppPassword',
  'com.atproto.server.updateEmail',
]);

export function isAuthScope(scope: unknown): scope is AuthScope {
  return typeof scope === 'string' && AUTH_SCOPE_VALUES.has(scope);
}

export function isBearerAccessScope(scope: unknown): scope is BearerAccessScope {
  return typeof scope === 'string' && BEARER_ACCESS_SCOPE_VALUES.has(scope);
}

export function isOAuthScope(scope: unknown): scope is string {
  const parts = oauthScopeParts(scope);
  return parts !== null &&
    parts.includes(OAUTH_PROFILE_SCOPE) &&
    parts.every(isRecognizedOAuthScopePart);
}

export function isOAuthPermissionScope(scope: unknown): scope is string {
  const parts = oauthScopeParts(scope);
  return parts !== null &&
    parts.includes(OAUTH_PROFILE_SCOPE) &&
    parts.some((part) => part !== OAUTH_PROFILE_SCOPE && grantsOAuthResourceAccess(part)) &&
    parts.every(isRecognizedOAuthScopePart);
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

export type RepoWriteAction = 'create' | 'update' | 'delete';

export function canAccessActorPreferences(access: AuthAccessContext): boolean {
  if (access.isTakendown || access.isSignupQueued) return false;
  if (access.isFullAccess || access.isAppPassword) return true;
  return access.isOAuth && oauthScopeAllowsTransitionGeneric(access.scope);
}

export function canAccessChat(access: AuthAccessContext): boolean {
  if (access.isTakendown || access.isSignupQueued) return false;
  if (access.isPrivileged) return true;
  return access.isOAuth && oauthScopeAllowsTransitionChat(access.scope);
}

export function canAccessFullAccount(access: AuthAccessContext): boolean {
  return access.isFullAccess && !access.isTakendown && !access.isSignupQueued;
}

export function canUseAppPasswordLevelAccess(access: AuthAccessContext): boolean {
  if (access.isTakendown || access.isSignupQueued) return false;
  if (access.isFullAccess || access.isAppPassword) return true;
  return access.isOAuth && oauthScopeAllowsTransitionGeneric(access.scope);
}

export function canWriteRepo(
  access: AuthAccessContext,
  collection: unknown,
  action: RepoWriteAction,
): boolean {
  if (access.isTakendown || access.isSignupQueued || typeof collection !== 'string') {
    return false;
  }
  if (access.isFullAccess || access.isAppPassword) return true;
  if (!access.isOAuth) return false;
  const parts = oauthScopeParts(access.scope);
  if (!parts) return false;
  if (parts.includes(OAUTH_TRANSITION_GENERIC)) return true;
  return parts.some((part) => oauthPermissionAllowsRepo(part, collection, action));
}

export function canUploadBlob(access: AuthAccessContext, mimeType: string): boolean {
  if (access.isTakendown || access.isSignupQueued) return false;
  if (access.isFullAccess || access.isAppPassword) return true;
  if (!access.isOAuth) return false;
  const parts = oauthScopeParts(access.scope);
  if (!parts) return false;
  if (parts.includes(OAUTH_TRANSITION_GENERIC)) return true;
  return parts.some((part) => oauthPermissionAllowsBlob(part, mimeType));
}

export function canMakeRpcCall(
  access: AuthAccessContext,
  lxm: string | null | undefined,
  aud: string | null | undefined,
): boolean {
  if (access.isTakendown || access.isSignupQueued) return false;
  if (access.isFullAccess) return true;
  if (access.isAppPassword) {
    return access.isPrivileged || !isChatRpc(lxm);
  }
  if (!access.isOAuth || !lxm || !aud) return false;
  const parts = oauthScopeParts(access.scope);
  if (!parts) return false;
  if (oauthScopeAllowsTransitionChat(access.scope) && isChatRpc(lxm)) return true;
  if (
    parts.includes(OAUTH_TRANSITION_GENERIC) &&
    !isChatRpc(lxm) &&
    !TRANSITION_GENERIC_BLOCKED_RPC.has(lxm)
  ) return true;
  return parts.some((part) => oauthPermissionAllowsRpc(part, lxm, aud));
}

function oauthScopeParts(scope: unknown): string[] | null {
  if (typeof scope !== 'string') return null;
  const parts = scope.split(/\s+/).filter(Boolean);
  return parts.length > 0 ? parts : null;
}

function isRecognizedOAuthScopePart(scope: string): boolean {
  if (scope === OAUTH_PROFILE_SCOPE || OAUTH_TRANSITION_SCOPES.has(scope)) return true;
  return parsePermissionScope(scope) !== null;
}

function grantsOAuthResourceAccess(scope: string): boolean {
  if (scope === OAUTH_TRANSITION_CHAT) return false;
  if (OAUTH_TRANSITION_SCOPES.has(scope)) return true;
  const parsed = parsePermissionScope(scope);
  return parsed !== null && parsed.resource !== 'include';
}

function oauthScopeAllowsTransitionGeneric(scope: string): boolean {
  return oauthScopeParts(scope)?.includes(OAUTH_TRANSITION_GENERIC) ?? false;
}

function oauthScopeAllowsTransitionChat(scope: string): boolean {
  const parts = oauthScopeParts(scope);
  return !!parts?.includes(OAUTH_TRANSITION_GENERIC) && parts.includes(OAUTH_TRANSITION_CHAT);
}

type ParsedPermissionScope =
  | { resource: 'repo'; collections: string[]; actions: RepoWriteAction[] | null }
  | { resource: 'rpc'; lxms: string[]; aud: string }
  | { resource: 'blob'; accepts: string[] }
  | { resource: 'account'; attr: string; action: 'read' | 'manage' }
  | { resource: 'identity'; attr: string }
  | { resource: 'include' };

function parsePermissionScope(scope: string): ParsedPermissionScope | null {
  if (!/^[\x21-\x7e]+$/.test(scope)) return null;
  const questionIndex = scope.indexOf('?');
  const head = questionIndex === -1 ? scope : scope.slice(0, questionIndex);
  const query = questionIndex === -1 ? '' : scope.slice(questionIndex + 1);
  if (!head) return null;

  const colonIndex = head.indexOf(':');
  const resource = colonIndex === -1 ? head : head.slice(0, colonIndex);
  const positional = colonIndex === -1 ? null : decodeScopeComponent(head.slice(colonIndex + 1));
  if (!resource || (positional !== null && positional === '') || !OAUTH_RESOURCE_TYPES.has(resource)) {
    return null;
  }

  const params = new URLSearchParams(query);
  switch (resource) {
    case 'repo':
      return parseRepoScope(positional, params);
    case 'rpc':
      return parseRpcScope(positional, params);
    case 'blob':
      return parseBlobScope(positional, params);
    case 'account':
      return parseAccountScope(positional, params);
    case 'identity':
      return parseIdentityScope(positional, params);
    case 'include':
      return positional && paramsHaveOnly(params, new Set(['aud'])) ? { resource: 'include' } : null;
  }
}

function parseRepoScope(positional: string | null, params: URLSearchParams): ParsedPermissionScope | null {
  if (!paramsHaveOnly(params, new Set(['collection', 'action']))) return null;
  if (positional !== null && params.has('collection')) return null;
  const collections = positional !== null ? [positional] : params.getAll('collection');
  if (!collections.length || collections.some((value) => value === '')) return null;
  const actionsRaw = params.getAll('action');
  const actions = actionsRaw.length
    ? unique(actionsRaw).filter((action): action is RepoWriteAction => REPO_ACTIONS.has(action))
    : null;
  if (actionsRaw.length && actions.length !== unique(actionsRaw).length) return null;
  return { resource: 'repo', collections, actions };
}

function parseRpcScope(positional: string | null, params: URLSearchParams): ParsedPermissionScope | null {
  if (!paramsHaveOnly(params, new Set(['lxm', 'aud']))) return null;
  if (positional !== null && params.has('lxm')) return null;
  const lxms = positional !== null ? [positional] : params.getAll('lxm');
  const audiences = params.getAll('aud');
  if (!lxms.length || lxms.some((value) => value === '') || audiences.length !== 1 || audiences[0] === '') {
    return null;
  }
  if (lxms.includes('*') && audiences[0] === '*') return null;
  return { resource: 'rpc', lxms, aud: audiences[0] };
}

function parseBlobScope(positional: string | null, params: URLSearchParams): ParsedPermissionScope | null {
  if (!paramsHaveOnly(params, new Set(['accept']))) return null;
  if (positional !== null && params.has('accept')) return null;
  const accepts = positional !== null ? [positional] : params.getAll('accept');
  if (!accepts.length || accepts.some((value) => value === '')) return null;
  return { resource: 'blob', accepts };
}

function parseAccountScope(positional: string | null, params: URLSearchParams): ParsedPermissionScope | null {
  if (!paramsHaveOnly(params, new Set(['attr', 'action']))) return null;
  if (positional !== null && params.has('attr')) return null;
  const attrs = positional !== null ? [positional] : params.getAll('attr');
  const actions = params.getAll('action');
  if (attrs.length !== 1 || attrs[0] === '' || actions.length > 1) return null;
  const action = actions[0] ?? 'read';
  if (!ACCOUNT_ACTIONS.has(action)) return null;
  return { resource: 'account', attr: attrs[0], action: action as 'read' | 'manage' };
}

function parseIdentityScope(positional: string | null, params: URLSearchParams): ParsedPermissionScope | null {
  if (!paramsHaveOnly(params, new Set(['attr']))) return null;
  if (positional !== null && params.has('attr')) return null;
  const attrs = positional !== null ? [positional] : params.getAll('attr');
  if (attrs.length !== 1 || attrs[0] === '') return null;
  return { resource: 'identity', attr: attrs[0] };
}

function paramsHaveOnly(params: URLSearchParams, allowed: ReadonlySet<string>): boolean {
  for (const key of params.keys()) {
    if (!allowed.has(key)) return false;
  }
  return true;
}

function decodeScopeComponent(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return '';
  }
}

function unique(values: string[]): string[] {
  return [...new Set(values)];
}

function oauthPermissionAllowsRepo(scope: string, collection: string, action: RepoWriteAction): boolean {
  const parsed = parsePermissionScope(scope);
  if (!parsed || parsed.resource !== 'repo') return false;
  if (!parsed.collections.includes('*') && !parsed.collections.includes(collection)) return false;
  return !parsed.actions || parsed.actions.includes(action);
}

function oauthPermissionAllowsBlob(scope: string, mimeType: string): boolean {
  const parsed = parsePermissionScope(scope);
  if (!parsed || parsed.resource !== 'blob') return false;
  return parsed.accepts.some((accept) => mimeMatches(accept, mimeType));
}

function oauthPermissionAllowsRpc(scope: string, lxm: string, aud: string): boolean {
  const parsed = parsePermissionScope(scope);
  if (!parsed || parsed.resource !== 'rpc') return false;
  const lxmAllowed = parsed.lxms.includes('*') || parsed.lxms.includes(lxm);
  const audAllowed = parsed.aud === '*' || parsed.aud === aud;
  return lxmAllowed && audAllowed;
}

function mimeMatches(accept: string, mimeType: string): boolean {
  const normalizedAccept = accept.toLowerCase();
  const normalizedMime = mimeType.toLowerCase();
  if (normalizedAccept === '*/*') return true;
  if (normalizedAccept.endsWith('/*')) {
    return normalizedMime.startsWith(`${normalizedAccept.slice(0, -1)}`);
  }
  return normalizedAccept === normalizedMime;
}

function isChatRpc(lxm: string | null | undefined): boolean {
  return typeof lxm === 'string' && lxm.startsWith('chat.bsky.');
}
