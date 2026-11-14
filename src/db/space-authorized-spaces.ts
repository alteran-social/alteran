import type { Env } from '../env';
import { consumeVerifiedSpacePrincipal, type VerifiedSpacePrincipal } from '../lib/oauth/space-principal';
import { restoreExplicitSpaceConsent } from '../lib/spaces/explicit-read-consent';
import { parseListSpacesRequest } from '../lib/spaces/list-spaces-request';
import { serializeOwnerSpacePage } from '../lib/spaces/list-spaces-response';
import { allowsSpacePermission } from '../lib/spaces/oauth-scopes';
import { selectOwnerSpacePage, type OwnerSpacePage, type OwnerSpacePageContext } from './space-owner-page';
import { assertLocalSpaceRepo } from './space-ref';
import { windowIsLive } from './space-read-auth';

type Complete = (request: Request, database: D1Database) => Promise<boolean>;
export type AuthorizedSpaces =
  | { readonly tag: 'found'; readonly body: string; readonly complete: Complete }
  | { readonly tag: 'scopeMissing' }
  | { readonly tag: 'unauthorized' };

/** List only a complete, explicitly granted local authority and Space type. */
export async function listAuthorizedOwnerSpaces(
  env: Env, principal: VerifiedSpacePrincipal, request: Request,
): Promise<AuthorizedSpaces> {
  try {
    const database = env.ALTERAN_DB;
    if (!consumeVerifiedSpacePrincipal(principal, request, database) || env.ALTERAN_DB !== database ||
      !windowIsLive(principal)) return denied();
    const parsed = parseListSpacesRequest(request);
    if (parsed.tag !== 'valid' || parsed.target.authorityDid !== principal.did) return denied();
    const consent = await restoreExplicitSpaceConsent(principal.grant.snapshot, principal.grant.digest, {
      subject: principal.did, accountIncarnation: principal.grant.accountIncarnation,
      clientId: principal.clientId, dpopJkt: principal.jkt,
      clientAuthMethod: principal.grant.clientAuthMethod, clientAuthKeyId: principal.grant.clientAuthKeyId,
      clientAuthKeyBinding: principal.grant.clientAuthKeyBinding,
    }, principal.scope);
    if (!consent || !windowIsLive(principal)) return denied();
    if (!consent.grants.some((grant) => allowsSpacePermission(grant.permission, {
      authority: parsed.target.authorityDid, spaceType: parsed.target.spaceType, skey: '*',
    }, { action: 'read_self' }))) return { tag: 'scopeMissing' };
    await assertLocalSpaceRepo(env, principal.did);
    if (request.signal.aborted || env.ALTERAN_DB !== database || !windowIsLive(principal)) return denied();
    const context: OwnerSpacePageContext = Object.freeze({ env, database, request, principal, target: parsed.target });
    const page = await selectOwnerSpacePage(context);
    if (!page) return denied();
    const body = serializeOwnerSpacePage(page);
    const complete = completion(context, page);
    return Object.freeze({ tag: 'found', body, complete });
  } catch {
    return denied();
  }
}

function completion(context: OwnerSpacePageContext, previous: OwnerSpacePage): Complete {
  let consumed = false;
  return async (request, database) => {
    if (consumed) return false;
    consumed = true;
    try {
      if (request !== context.request || database !== context.database || context.env.ALTERAN_DB !== database ||
        request.signal.aborted || !windowIsLive(context.principal)) return false;
      const current = await selectOwnerSpacePage(context);
      return !!current && samePage(previous, current) && !request.signal.aborted &&
        context.env.ALTERAN_DB === database && windowIsLive(context.principal);
    } catch {
      return false;
    }
  };
}

function samePage(left: OwnerSpacePage, right: OwnerSpacePage): boolean {
  if (left.cursor !== right.cursor || left.entries.length !== right.entries.length) return false;
  for (let index = 0; index < left.entries.length; index++) {
    const first = left.entries[index], second = right.entries[index];
    if (first.space !== second.space || first.nonce !== second.nonce || first.createdAt !== second.createdAt ||
      (first.repo === null) !== (second.repo === null)) return false;
    if (first.repo && second.repo) {
      if (first.repo.revision !== second.repo.revision || first.repo.generation !== second.repo.generation ||
        first.repo.mutationId !== second.repo.mutationId || first.repo.epochId !== second.repo.epochId ||
        first.repo.setHash.length !== second.repo.setHash.length) return false;
      for (let offset = 0; offset < first.repo.setHash.length; offset++) {
        if (first.repo.setHash[offset] !== second.repo.setHash[offset]) return false;
      }
    }
  }
  return true;
}

function denied(): AuthorizedSpaces { return { tag: 'unauthorized' }; }
