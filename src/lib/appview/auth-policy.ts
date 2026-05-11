import type { AuthScope } from './types';

const DEFAULT_ACCESS_SCOPE: AuthScope = 'com.atproto.access';
export const TAKENDOWN_SCOPE: AuthScope = 'com.atproto.takendown';

export const PRIVILEGED_SCOPES: ReadonlySet<AuthScope> = new Set([
  'com.atproto.access',
  'com.atproto.appPassPrivileged',
]);

export const PRIVILEGED_METHODS: ReadonlySet<string> = new Set([
  'chat.bsky.actor.deleteAccount',
  'chat.bsky.actor.exportAccountData',
  'chat.bsky.convo.deleteMessageForSelf',
  'chat.bsky.convo.getConvo',
  'chat.bsky.convo.getConvoForMembers',
  'chat.bsky.convo.getLog',
  'chat.bsky.convo.getMessages',
  'chat.bsky.convo.leaveConvo',
  'chat.bsky.convo.listConvos',
  'chat.bsky.convo.muteConvo',
  'chat.bsky.convo.sendMessage',
  'chat.bsky.convo.sendMessageBatch',
  'chat.bsky.convo.unmuteConvo',
  'chat.bsky.convo.updateRead',
  'com.atproto.server.createAccount',
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

export function resolveAuthScope(scope: unknown): AuthScope {
  if (typeof scope !== 'string') {
    return DEFAULT_ACCESS_SCOPE;
  }

  switch (scope) {
    case 'access':
      return 'com.atproto.access';
    case 'com.atproto.access':
    case 'com.atproto.appPass':
    case 'com.atproto.appPassPrivileged':
    case 'com.atproto.signupQueued':
    case 'com.atproto.takendown':
      return scope;
    default:
      console.warn('Unknown auth scope, treating as access scope', scope);
      return DEFAULT_ACCESS_SCOPE;
  }
}
