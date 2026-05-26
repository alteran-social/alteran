export const RouteKind = {
  Astro: 'astro',
  Debug: 'debug',
  Root: 'root',
  WorkerOnly: 'worker-only',
};

export const CORE_ROUTES = [
  { kind: RouteKind.Astro, pattern: '/.well-known/atproto-did', entrypoint: './src/entrypoints/well-known/atproto-did.ts' },
  { kind: RouteKind.Astro, pattern: '/.well-known/did.json', entrypoint: './src/entrypoints/well-known/did.json.ts' },
  { kind: RouteKind.Astro, pattern: '/.well-known/oauth-authorization-server', entrypoint: './src/entrypoints/well-known/oauth-authorization-server.ts' },
  { kind: RouteKind.Astro, pattern: '/.well-known/oauth-protected-resource', entrypoint: './src/entrypoints/well-known/oauth-protected-resource.ts' },
  { kind: RouteKind.Astro, pattern: '/well-known/atproto-did', entrypoint: './src/pages/well-known/atproto-did.ts' },
  { kind: RouteKind.Astro, pattern: '/well-known/did.json', entrypoint: './src/pages/well-known/did.json.ts' },
  { kind: RouteKind.Astro, pattern: '/well-known/oauth-authorization-server', entrypoint: './src/pages/well-known/oauth-authorization-server.ts' },
  { kind: RouteKind.Astro, pattern: '/well-known/oauth-protected-resource', entrypoint: './src/pages/well-known/oauth-protected-resource.ts' },
  { kind: RouteKind.Astro, pattern: '/health', entrypoint: './src/pages/health.ts' },
  { kind: RouteKind.Astro, pattern: '/oauth/authorize', entrypoint: './src/pages/oauth/authorize.ts' },
  { kind: RouteKind.Astro, pattern: '/oauth/consent', entrypoint: './src/pages/oauth/consent.ts' },
  { kind: RouteKind.Astro, pattern: '/oauth/jwks', entrypoint: './src/pages/oauth/jwks.ts' },
  { kind: RouteKind.Astro, pattern: '/oauth/par', entrypoint: './src/pages/oauth/par.ts' },
  { kind: RouteKind.Astro, pattern: '/oauth/revoke', entrypoint: './src/pages/oauth/revoke.ts' },
  { kind: RouteKind.Astro, pattern: '/oauth/token', entrypoint: './src/pages/oauth/token.ts' },
  { kind: RouteKind.Astro, pattern: '/ready', entrypoint: './src/pages/ready.ts' },
  { kind: RouteKind.Astro, pattern: '/xrpc/app.bsky.actor.getPreferences', entrypoint: './src/pages/xrpc/app.bsky.actor.getPreferences.ts' },
  { kind: RouteKind.Astro, pattern: '/xrpc/app.bsky.actor.putPreferences', entrypoint: './src/pages/xrpc/app.bsky.actor.putPreferences.ts' },
  { kind: RouteKind.Astro, pattern: '/xrpc/app.bsky.labeler.getServices', entrypoint: './src/pages/xrpc/app.bsky.labeler.getServices.ts' },
  { kind: RouteKind.Astro, pattern: '/xrpc/app.bsky.unspecced.getAgeAssuranceState', entrypoint: './src/pages/xrpc/app.bsky.unspecced.getAgeAssuranceState.ts' },
  { kind: RouteKind.Astro, pattern: '/xrpc/app.bsky.unspecced.getConfig', entrypoint: './src/pages/xrpc/app.bsky.unspecced.getConfig.ts' },
  { kind: RouteKind.Astro, pattern: '/xrpc/chat.bsky.convo.getLog', entrypoint: './src/pages/xrpc/chat.bsky.convo.getLog.ts' },
  { kind: RouteKind.Astro, pattern: '/xrpc/chat.bsky.convo.listConvos', entrypoint: './src/pages/xrpc/chat.bsky.convo.listConvos.ts' },
  { kind: RouteKind.Astro, pattern: '/xrpc/com.atproto.identity.getRecommendedDidCredentials', entrypoint: './src/pages/xrpc/com.atproto.identity.getRecommendedDidCredentials.ts' },
  { kind: RouteKind.Astro, pattern: '/xrpc/com.atproto.identity.requestPlcOperationSignature', entrypoint: './src/pages/xrpc/com.atproto.identity.requestPlcOperationSignature.ts' },
  { kind: RouteKind.Astro, pattern: '/xrpc/com.atproto.identity.resolveHandle', entrypoint: './src/pages/xrpc/com.atproto.identity.resolveHandle.ts' },
  { kind: RouteKind.Astro, pattern: '/xrpc/com.atproto.identity.signPlcOperation', entrypoint: './src/pages/xrpc/com.atproto.identity.signPlcOperation.ts' },
  { kind: RouteKind.Astro, pattern: '/xrpc/com.atproto.identity.submitPlcOperation', entrypoint: './src/pages/xrpc/com.atproto.identity.submitPlcOperation.ts' },
  { kind: RouteKind.Astro, pattern: '/xrpc/com.atproto.identity.updateHandle', entrypoint: './src/pages/xrpc/com.atproto.identity.updateHandle.ts' },
  { kind: RouteKind.Astro, pattern: '/xrpc/com.atproto.repo.applyWrites', entrypoint: './src/pages/xrpc/com.atproto.repo.applyWrites.ts' },
  { kind: RouteKind.Astro, pattern: '/xrpc/com.atproto.repo.createRecord', entrypoint: './src/pages/xrpc/com.atproto.repo.createRecord.ts' },
  { kind: RouteKind.Astro, pattern: '/xrpc/com.atproto.repo.deleteRecord', entrypoint: './src/pages/xrpc/com.atproto.repo.deleteRecord.ts' },
  { kind: RouteKind.Astro, pattern: '/xrpc/com.atproto.repo.describeRepo', entrypoint: './src/pages/xrpc/com.atproto.repo.describeRepo.ts' },
  { kind: RouteKind.Astro, pattern: '/xrpc/com.atproto.repo.getRecord', entrypoint: './src/pages/xrpc/com.atproto.repo.getRecord.ts' },
  { kind: RouteKind.Astro, pattern: '/xrpc/com.atproto.repo.listMissingBlobs', entrypoint: './src/pages/xrpc/com.atproto.repo.listMissingBlobs.ts' },
  { kind: RouteKind.Astro, pattern: '/xrpc/com.atproto.repo.listRecords', entrypoint: './src/pages/xrpc/com.atproto.repo.listRecords.ts' },
  { kind: RouteKind.Astro, pattern: '/xrpc/com.atproto.repo.putRecord', entrypoint: './src/pages/xrpc/com.atproto.repo.putRecord.ts' },
  { kind: RouteKind.Astro, pattern: '/xrpc/com.atproto.repo.uploadBlob', entrypoint: './src/pages/xrpc/com.atproto.repo.uploadBlob.ts' },
  { kind: RouteKind.Astro, pattern: '/xrpc/com.atproto.server.checkAccountStatus', entrypoint: './src/pages/xrpc/com.atproto.server.checkAccountStatus.ts' },
  { kind: RouteKind.Astro, pattern: '/xrpc/com.atproto.server.createAppPassword', entrypoint: './src/pages/xrpc/com.atproto.server.createAppPassword.ts' },
  { kind: RouteKind.Astro, pattern: '/xrpc/com.atproto.server.createSession', entrypoint: './src/pages/xrpc/com.atproto.server.createSession.ts' },
  { kind: RouteKind.Astro, pattern: '/xrpc/com.atproto.server.deleteSession', entrypoint: './src/pages/xrpc/com.atproto.server.deleteSession.ts' },
  { kind: RouteKind.Astro, pattern: '/xrpc/com.atproto.server.describeServer', entrypoint: './src/pages/xrpc/com.atproto.server.describeServer.ts' },
  { kind: RouteKind.Astro, pattern: '/xrpc/com.atproto.server.getServiceAuth', entrypoint: './src/pages/xrpc/com.atproto.server.getServiceAuth.ts' },
  { kind: RouteKind.Astro, pattern: '/xrpc/com.atproto.server.getSession', entrypoint: './src/pages/xrpc/com.atproto.server.getSession.ts' },
  { kind: RouteKind.Astro, pattern: '/xrpc/com.atproto.server.listAppPasswords', entrypoint: './src/pages/xrpc/com.atproto.server.listAppPasswords.ts' },
  { kind: RouteKind.Astro, pattern: '/xrpc/com.atproto.server.refreshSession', entrypoint: './src/pages/xrpc/com.atproto.server.refreshSession.ts' },
  { kind: RouteKind.Astro, pattern: '/xrpc/com.atproto.server.revokeAppPassword', entrypoint: './src/pages/xrpc/com.atproto.server.revokeAppPassword.ts' },
  { kind: RouteKind.Astro, pattern: '/xrpc/com.atproto.sync.getBlob', entrypoint: './src/pages/xrpc/com.atproto.sync.getBlob.ts' },
  { kind: RouteKind.Astro, pattern: '/xrpc/com.atproto.sync.getBlocks', entrypoint: './src/pages/xrpc/com.atproto.sync.getBlocks.ts' },
  { kind: RouteKind.Astro, pattern: '/xrpc/com.atproto.sync.getBlocks.json', entrypoint: './src/pages/xrpc/com.atproto.sync.getBlocks.json.ts' },
  { kind: RouteKind.Astro, pattern: '/xrpc/com.atproto.sync.getCheckout', entrypoint: './src/pages/xrpc/com.atproto.sync.getCheckout.ts' },
  { kind: RouteKind.Astro, pattern: '/xrpc/com.atproto.sync.getCheckout.json', entrypoint: './src/pages/xrpc/com.atproto.sync.getCheckout.json.ts' },
  { kind: RouteKind.Astro, pattern: '/xrpc/com.atproto.sync.getHead', entrypoint: './src/pages/xrpc/com.atproto.sync.getHead.ts' },
  { kind: RouteKind.Astro, pattern: '/xrpc/com.atproto.sync.getLatestCommit', entrypoint: './src/pages/xrpc/com.atproto.sync.getLatestCommit.ts' },
  { kind: RouteKind.Astro, pattern: '/xrpc/com.atproto.sync.getRecord', entrypoint: './src/pages/xrpc/com.atproto.sync.getRecord.ts' },
  { kind: RouteKind.Astro, pattern: '/xrpc/com.atproto.sync.getRepo', entrypoint: './src/pages/xrpc/com.atproto.sync.getRepo.ts' },
  { kind: RouteKind.Astro, pattern: '/xrpc/com.atproto.sync.getRepo.json', entrypoint: './src/pages/xrpc/com.atproto.sync.getRepo.json.ts' },
  { kind: RouteKind.Astro, pattern: '/xrpc/com.atproto.sync.getRepo.range', entrypoint: './src/pages/xrpc/com.atproto.sync.getRepo.range.ts' },
  { kind: RouteKind.Astro, pattern: '/xrpc/com.atproto.sync.getRepoStatus', entrypoint: './src/pages/xrpc/com.atproto.sync.getRepoStatus.ts' },
  { kind: RouteKind.Astro, pattern: '/xrpc/com.atproto.sync.listBlobs', entrypoint: './src/pages/xrpc/com.atproto.sync.listBlobs.ts' },
  { kind: RouteKind.Astro, pattern: '/xrpc/com.atproto.sync.listRepos', entrypoint: './src/pages/xrpc/com.atproto.sync.listRepos.ts' },
  { kind: RouteKind.Astro, pattern: '/xrpc/[...nsid]', entrypoint: './src/pages/xrpc/[...nsid].ts' },
];

export const ROOT_ROUTE = {
  kind: RouteKind.Root,
  pattern: '/',
  entrypoint: './src/handlers/root.ts',
};

export const DEBUG_ROUTES = [
  { kind: RouteKind.Debug, pattern: '/debug/blob/[...key]', entrypoint: './src/pages/debug/blob/[...key].ts' },
  { kind: RouteKind.Debug, pattern: '/debug/db/bootstrap', entrypoint: './src/pages/debug/db/bootstrap.ts' },
  { kind: RouteKind.Debug, pattern: '/debug/db/commits', entrypoint: './src/pages/debug/db/commits.ts' },
  { kind: RouteKind.Debug, pattern: '/debug/gc/blobs', entrypoint: './src/pages/debug/gc/blobs.ts' },
  { kind: RouteKind.Debug, pattern: '/debug/record', entrypoint: './src/pages/debug/record.ts' },
  { kind: RouteKind.Debug, pattern: '/debug/sequencer', entrypoint: './src/pages/debug/sequencer.ts' },
];

export const WORKER_ONLY_ROUTES = [
  { kind: RouteKind.WorkerOnly, pattern: '/debug/sequencer' },
  { kind: RouteKind.WorkerOnly, pattern: '/xrpc/com.atproto.sync.subscribeRepos' },
];

export function integrationRoutes({ includeRootEndpoint = false, debugRoutes = false } = {}) {
  const routes = CORE_ROUTES.slice();
  if (includeRootEndpoint) routes.unshift(ROOT_ROUTE);
  if (debugRoutes) routes.push(...DEBUG_ROUTES);
  return routes;
}

export const ROUTES = [
  ROOT_ROUTE,
  ...CORE_ROUTES,
  ...DEBUG_ROUTES,
  ...WORKER_ONLY_ROUTES,
];
