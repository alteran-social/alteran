import { parsePermissionScope, type RepoWriteAction } from '../auth-scope';

export type ConsentPermission =
  | { readonly tag: 'profile' }
  | { readonly tag: 'transition'; readonly scope: string }
  | { readonly tag: 'repo'; readonly collection: string; readonly actions: readonly RepoWriteAction[] }
  | { readonly tag: 'blob'; readonly accepts: readonly string[] }
  | { readonly tag: 'rpc'; readonly methods: readonly string[]; readonly audience: string }
  | { readonly tag: 'account'; readonly attribute: string; readonly action: 'read' | 'manage' }
  | { readonly tag: 'identity'; readonly attribute: string };

const ALL_REPO_ACTIONS: readonly RepoWriteAction[] = ['create', 'update', 'delete'];

const TRANSITION_DESCRIPTIONS: Readonly<Record<string, string>> = {
  'transition:generic':
    'Full access to your repository: create, update and delete any record, upload blobs, read and change preferences, and call most services on your behalf',
  'transition:chat.bsky': 'Read and send your direct messages',
  'transition:email': 'Read your account email address',
};

/**
 * Turns a granted scope string into the list of permissions shown on the
 * consent screen. Several `repo:` scopes for one collection collapse into a
 * single entry so the user sees every action on that collection together.
 */
export function consentPermissions(scope: string): readonly ConsentPermission[] {
  const permissions: ConsentPermission[] = [];
  const repoActions = new Map<string, Set<RepoWriteAction>>();

  for (const part of scope.split(' ').filter(Boolean)) {
    if (part === 'atproto') {
      permissions.push({ tag: 'profile' });
      continue;
    }
    if (part in TRANSITION_DESCRIPTIONS) {
      permissions.push({ tag: 'transition', scope: part });
      continue;
    }
    const parsed = parsePermissionScope(part);
    if (!parsed) continue;
    switch (parsed.resource) {
      case 'repo':
        for (const collection of parsed.collections) {
          const actions = repoActions.get(collection) ?? new Set<RepoWriteAction>();
          for (const action of parsed.actions ?? ALL_REPO_ACTIONS) actions.add(action);
          repoActions.set(collection, actions);
        }
        break;
      case 'blob':
        permissions.push({ tag: 'blob', accepts: parsed.accepts });
        break;
      case 'rpc':
        permissions.push({ tag: 'rpc', methods: parsed.lxms, audience: parsed.aud });
        break;
      case 'account':
        permissions.push({ tag: 'account', attribute: parsed.attr, action: parsed.action });
        break;
      case 'identity':
        permissions.push({ tag: 'identity', attribute: parsed.attr });
        break;
    }
  }

  for (const [collection, actions] of repoActions) {
    permissions.push({
      tag: 'repo',
      collection,
      actions: ALL_REPO_ACTIONS.filter((action) => actions.has(action)),
    });
  }
  return permissions;
}

export function describeConsentPermission(permission: ConsentPermission): string {
  switch (permission.tag) {
    case 'profile':
      return 'Know which account you are';
    case 'transition':
      return TRANSITION_DESCRIPTIONS[permission.scope] ?? permission.scope;
    case 'repo': {
      const target = permission.collection === '*'
        ? 'any collection'
        : `the collection ${permission.collection}`;
      return `${capitalize(joinWords(permission.actions))} records in ${target}`;
    }
    case 'blob':
      return permission.accepts.includes('*/*')
        ? 'Upload files of any type'
        : `Upload files of type ${joinWords(permission.accepts)}`;
    case 'rpc': {
      const methods = permission.methods.includes('*') ? 'any method' : joinWords(permission.methods);
      const audience = permission.audience === '*' ? 'any service' : permission.audience;
      return `Call ${methods} on ${audience} on your behalf`;
    }
    case 'account':
      return `${permission.action === 'manage' ? 'Read and change' : 'Read'} your account ${permission.attribute}`;
    case 'identity':
      return permission.attribute === '*'
        ? 'Change your identity, including your handle and signing keys'
        : `Change your identity ${permission.attribute}`;
  }
}

function joinWords(words: readonly string[]): string {
  if (words.length <= 1) return words.join('');
  return `${words.slice(0, -1).join(', ')} and ${words[words.length - 1]}`;
}

function capitalize(text: string): string {
  return text.charAt(0).toUpperCase() + text.slice(1);
}
