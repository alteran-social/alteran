import { DID } from './spaces-authorized-read';
import { EMPTY, policyFixture } from './spaces-policy-read';
import { signResourceDpop } from './oauth';
import { verifyResourceRequest } from '../../src/lib/oauth/resource';

export const LIST_ENDPOINT = 'https://pds.example/xrpc/com.atproto.space.listRecords';
export type GenesisFixture = Awaited<ReturnType<typeof policyFixture>>;

export async function signedGenesisRequest(f: GenesisFixture, options: {
  env?: GenesisFixture['env']; space?: string; repo?: string; query?: Record<string, string>; signal?: AbortSignal;
} = {}) {
  const env = options.env ?? f.env;
  const params = new URLSearchParams({ space: options.space ?? EMPTY, repo: options.repo ?? DID, ...options.query });
  const dpop = await signResourceDpop(env, f.key, 'GET', LIST_ENDPOINT, f.tokens.accessJwt);
  return new Request(`${LIST_ENDPOINT}?${params}`, {
    headers: { authorization: `DPoP ${f.tokens.accessJwt}`, dpop }, signal: options.signal,
  });
}

export async function genesisPrincipal(f: GenesisFixture, env: GenesisFixture['env'] = f.env) {
  const request = await signedGenesisRequest(f, { env });
  const context = await verifyResourceRequest(env, request);
  if (!context?.spacePrincipal) throw new Error('Missing verified list principal');
  return { request, principal: context.spacePrincipal };
}

export function listContext(env: GenesisFixture['env'], request: Request) {
  return { locals: { env }, request, url: new URL(request.url) } as never;
}
