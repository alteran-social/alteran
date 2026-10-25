import { AuthScope, isBearerAccessScope, type BearerAccessScope } from '../auth-scope';

export const TAKENDOWN_SCOPE: BearerAccessScope = AuthScope.Takendown;

export const PRIVILEGED_SCOPES: ReadonlySet<BearerAccessScope> = new Set([
  AuthScope.Access,
  AuthScope.AppPassPrivileged,
]);

export const PROTECTED_METHODS: ReadonlySet<string> = new Set([
  'com.atproto.admin.sendEmail',
  'com.atproto.identity.requestPlcOperationSignature',
  'com.atproto.identity.signPlcOperation',
  'com.atproto.identity.updateHandle',
  'com.atproto.server.activateAccount',
  'com.atproto.server.confirmEmail',
  'com.atproto.server.createAppPassword',
  'com.atproto.server.deactivateAccount',
  'com.atproto.server.getAccountInviteCodes',
  'com.atproto.server.getSession',
  'com.atproto.server.listAppPasswords',
  'com.atproto.server.requestAccountDelete',
  'com.atproto.server.requestEmailConfirmation',
  'com.atproto.server.requestEmailUpdate',
  'com.atproto.server.revokeAppPassword',
  'com.atproto.server.updateEmail',
]);

export function resolveAuthScope(scope: unknown): BearerAccessScope | null {
  return isBearerAccessScope(scope) ? scope : null;
}
