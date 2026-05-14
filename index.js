import { readFileSync } from 'node:fs';
import { isAbsolute, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const CORE_ROUTES = [
  { pattern: '/.well-known/atproto-did', entrypoint: './src/entrypoints/well-known/atproto-did.ts' },
  { pattern: '/.well-known/did.json', entrypoint: './src/entrypoints/well-known/did.json.ts' },
  { pattern: '/.well-known/oauth-authorization-server', entrypoint: './src/entrypoints/well-known/oauth-authorization-server.ts' },
  { pattern: '/.well-known/oauth-protected-resource', entrypoint: './src/entrypoints/well-known/oauth-protected-resource.ts' },
  { pattern: '/well-known/atproto-did', entrypoint: './src/pages/well-known/atproto-did.ts' },
  { pattern: '/well-known/did.json', entrypoint: './src/pages/well-known/did.json.ts' },
  { pattern: '/well-known/oauth-authorization-server', entrypoint: './src/pages/well-known/oauth-authorization-server.ts' },
  { pattern: '/well-known/oauth-protected-resource', entrypoint: './src/pages/well-known/oauth-protected-resource.ts' },
  { pattern: '/health', entrypoint: './src/pages/health.ts' },
  { pattern: '/oauth/authorize', entrypoint: './src/pages/oauth/authorize.ts' },
  { pattern: '/oauth/consent', entrypoint: './src/pages/oauth/consent.ts' },
  { pattern: '/oauth/jwks', entrypoint: './src/pages/oauth/jwks.ts' },
  { pattern: '/oauth/par', entrypoint: './src/pages/oauth/par.ts' },
  { pattern: '/oauth/revoke', entrypoint: './src/pages/oauth/revoke.ts' },
  { pattern: '/oauth/token', entrypoint: './src/pages/oauth/token.ts' },
  { pattern: '/ready', entrypoint: './src/pages/ready.ts' },
  { pattern: '/xrpc/com.atproto.identity.getRecommendedDidCredentials', entrypoint: './src/pages/xrpc/com.atproto.identity.getRecommendedDidCredentials.ts' },
  { pattern: '/xrpc/com.atproto.identity.requestPlcOperationSignature', entrypoint: './src/pages/xrpc/com.atproto.identity.requestPlcOperationSignature.ts' },
  { pattern: '/xrpc/com.atproto.identity.resolveHandle', entrypoint: './src/pages/xrpc/com.atproto.identity.resolveHandle.ts' },
  { pattern: '/xrpc/com.atproto.identity.submitPlcOperation', entrypoint: './src/pages/xrpc/com.atproto.identity.submitPlcOperation.ts' },
  { pattern: '/xrpc/com.atproto.identity.updateHandle', entrypoint: './src/pages/xrpc/com.atproto.identity.updateHandle.ts' },
  { pattern: '/xrpc/com.atproto.repo.applyWrites', entrypoint: './src/pages/xrpc/com.atproto.repo.applyWrites.ts' },
  { pattern: '/xrpc/com.atproto.repo.createRecord', entrypoint: './src/pages/xrpc/com.atproto.repo.createRecord.ts' },
  { pattern: '/xrpc/com.atproto.repo.deleteRecord', entrypoint: './src/pages/xrpc/com.atproto.repo.deleteRecord.ts' },
  { pattern: '/xrpc/com.atproto.repo.describeRepo', entrypoint: './src/pages/xrpc/com.atproto.repo.describeRepo.ts' },
  { pattern: '/xrpc/com.atproto.repo.getRecord', entrypoint: './src/pages/xrpc/com.atproto.repo.getRecord.ts' },
  { pattern: '/xrpc/com.atproto.repo.listMissingBlobs', entrypoint: './src/pages/xrpc/com.atproto.repo.listMissingBlobs.ts' },
  { pattern: '/xrpc/com.atproto.repo.listRecords', entrypoint: './src/pages/xrpc/com.atproto.repo.listRecords.ts' },
  { pattern: '/xrpc/com.atproto.repo.putRecord', entrypoint: './src/pages/xrpc/com.atproto.repo.putRecord.ts' },
  { pattern: '/xrpc/com.atproto.repo.uploadBlob', entrypoint: './src/pages/xrpc/com.atproto.repo.uploadBlob.ts' },
  { pattern: '/xrpc/com.atproto.server.checkAccountStatus', entrypoint: './src/pages/xrpc/com.atproto.server.checkAccountStatus.ts' },
  { pattern: '/xrpc/com.atproto.server.createAppPassword', entrypoint: './src/pages/xrpc/com.atproto.server.createAppPassword.ts' },
  { pattern: '/xrpc/com.atproto.server.createSession', entrypoint: './src/pages/xrpc/com.atproto.server.createSession.ts' },
  { pattern: '/xrpc/com.atproto.server.deleteSession', entrypoint: './src/pages/xrpc/com.atproto.server.deleteSession.ts' },
  { pattern: '/xrpc/com.atproto.server.listAppPasswords', entrypoint: './src/pages/xrpc/com.atproto.server.listAppPasswords.ts' },
  { pattern: '/xrpc/com.atproto.server.revokeAppPassword', entrypoint: './src/pages/xrpc/com.atproto.server.revokeAppPassword.ts' },
  { pattern: '/xrpc/com.atproto.server.describeServer', entrypoint: './src/pages/xrpc/com.atproto.server.describeServer.ts' },
  { pattern: '/xrpc/com.atproto.server.getSession', entrypoint: './src/pages/xrpc/com.atproto.server.getSession.ts' },
  { pattern: '/xrpc/com.atproto.server.refreshSession', entrypoint: './src/pages/xrpc/com.atproto.server.refreshSession.ts' },
  { pattern: '/xrpc/com.atproto.sync.getBlocks', entrypoint: './src/pages/xrpc/com.atproto.sync.getBlocks.ts' },
  { pattern: '/xrpc/com.atproto.sync.getBlocks.json', entrypoint: './src/pages/xrpc/com.atproto.sync.getBlocks.json.ts' },
  { pattern: '/xrpc/com.atproto.sync.getCheckout', entrypoint: './src/pages/xrpc/com.atproto.sync.getCheckout.ts' },
  { pattern: '/xrpc/com.atproto.sync.getCheckout.json', entrypoint: './src/pages/xrpc/com.atproto.sync.getCheckout.json.ts' },
  { pattern: '/xrpc/com.atproto.sync.getBlob', entrypoint: './src/pages/xrpc/com.atproto.sync.getBlob.ts' },
  { pattern: '/xrpc/com.atproto.sync.getHead', entrypoint: './src/pages/xrpc/com.atproto.sync.getHead.ts' },
  { pattern: '/xrpc/com.atproto.sync.getLatestCommit', entrypoint: './src/pages/xrpc/com.atproto.sync.getLatestCommit.ts' },
  { pattern: '/xrpc/com.atproto.sync.getRecord', entrypoint: './src/pages/xrpc/com.atproto.sync.getRecord.ts' },
  { pattern: '/xrpc/com.atproto.sync.getRepo', entrypoint: './src/pages/xrpc/com.atproto.sync.getRepo.ts' },
  { pattern: '/xrpc/com.atproto.sync.getRepoStatus', entrypoint: './src/pages/xrpc/com.atproto.sync.getRepoStatus.ts' },
  { pattern: '/xrpc/com.atproto.sync.getRepo.json', entrypoint: './src/pages/xrpc/com.atproto.sync.getRepo.json.ts' },
  { pattern: '/xrpc/com.atproto.sync.getRepo.range', entrypoint: './src/pages/xrpc/com.atproto.sync.getRepo.range.ts' },
  { pattern: '/xrpc/com.atproto.sync.listBlobs', entrypoint: './src/pages/xrpc/com.atproto.sync.listBlobs.ts' },
  { pattern: '/xrpc/com.atproto.sync.listRepos', entrypoint: './src/pages/xrpc/com.atproto.sync.listRepos.ts' },
  // Additional atproto endpoints
  { pattern: '/xrpc/com.atproto.identity.signPlcOperation', entrypoint: './src/pages/xrpc/com.atproto.identity.signPlcOperation.ts' },
  { pattern: '/xrpc/com.atproto.server.getServiceAuth', entrypoint: './src/pages/xrpc/com.atproto.server.getServiceAuth.ts' },
  // AppView proxy endpoints (bsky) — local-only where required
  { pattern: '/xrpc/app.bsky.actor.getPreferences', entrypoint: './src/pages/xrpc/app.bsky.actor.getPreferences.ts' },
  { pattern: '/xrpc/app.bsky.actor.putPreferences', entrypoint: './src/pages/xrpc/app.bsky.actor.putPreferences.ts' },
  { pattern: '/xrpc/app.bsky.labeler.getServices', entrypoint: './src/pages/xrpc/app.bsky.labeler.getServices.ts' },
  { pattern: '/xrpc/app.bsky.unspecced.getAgeAssuranceState', entrypoint: './src/pages/xrpc/app.bsky.unspecced.getAgeAssuranceState.ts' },
  { pattern: '/xrpc/app.bsky.unspecced.getConfig', entrypoint: './src/pages/xrpc/app.bsky.unspecced.getConfig.ts' },
  // Catchall for proxied XRPC endpoints (app.bsky.*, chat.bsky.*, tools.ozone.*)
  { pattern: '/xrpc/[...nsid]', entrypoint: './src/pages/xrpc/[...nsid].ts' },
  // Chat endpoints (proxied)
  { pattern: '/xrpc/chat.bsky.convo.getLog', entrypoint: './src/pages/xrpc/chat.bsky.convo.getLog.ts' },
  { pattern: '/xrpc/chat.bsky.convo.listConvos', entrypoint: './src/pages/xrpc/chat.bsky.convo.listConvos.ts' },
];

const ROOT_ROUTE = {
  pattern: '/',
  entrypoint: './src/handlers/root.ts',
};

const DEBUG_ROUTES = [
  { pattern: '/debug/blob/[...key]', entrypoint: './src/pages/debug/blob/[...key].ts' },
  { pattern: '/debug/db/bootstrap', entrypoint: './src/pages/debug/db/bootstrap.ts' },
  { pattern: '/debug/db/commits', entrypoint: './src/pages/debug/db/commits.ts' },
  { pattern: '/debug/gc/blobs', entrypoint: './src/pages/debug/gc/blobs.ts' },
  { pattern: '/debug/record', entrypoint: './src/pages/debug/record.ts' },
  { pattern: '/debug/sequencer', entrypoint: './src/pages/debug/sequencer.ts' },
];

const pkgRoot = new URL('.', import.meta.url);

const resolvePackagePath = (relative) => fileURLToPath(new URL(relative, pkgRoot));

const replaceRequired = (content, search, replacement) => {
  if (!content.includes(search)) {
    throw new Error(`[alteran] Unable to derive injected env types: missing marker "${search}"`);
  }

  return content.replace(search, replacement);
};

const buildInjectedEnvTypes = () => {
  const publicEnvTypes = readFileSync(resolvePackagePath('./types/public-env.d.ts'), 'utf-8');
  const ambientEnvTypes = [
    ['export type Env = {', 'type AlteranEnv = {'],
    ['export type PdsLocals = {', 'type AlteranPdsLocals = {'],
    ['env: Env;', 'env: AlteranEnv;'],
  ].reduce(
    (content, [search, replacement]) => replaceRequired(content, search, replacement),
    publicEnvTypes
  );

  return `/// <reference types="astro/client" />

${ambientEnvTypes}

declare global {
  interface Env extends AlteranEnv {}

  namespace App {
    interface Locals extends AlteranPdsLocals {}
  }
}

export type Env = globalThis.Env;
export type PdsLocals = globalThis.App.Locals;
export {};
`;
};

export default function alteran(options = {}) {
  const {
    debugRoutes = false,
    includeRootEndpoint = false,
  } = options;

  const middlewareEntrypoint = resolvePackagePath('./src/middleware.ts');
  const cloudflareServerAdapter = resolvePackagePath('./src/_worker.ts');

  const routes = CORE_ROUTES.slice();
  if (includeRootEndpoint) {
    routes.unshift(ROOT_ROUTE);
  }
  if (debugRoutes) {
    routes.push(...DEBUG_ROUTES);
  }

  return {
    name: 'alteran',
    hooks: {
      'astro:config:setup'({ config, updateConfig, addMiddleware, injectRoute, logger }) {
        if (config.output !== 'server') {
          updateConfig({ output: 'server' });
        }

        // Replace the cloudflare adapter's entrypoint with alteran's wrapper.
        // The wrapper imports `handle` from `@astrojs/cloudflare/handler` and
        // composes PDS concerns (CORS preflight, Sequencer routing, config
        // validation, relay notification) ahead of Astro's render pipeline.
        // It also exports `Sequencer` so the Durable Object class lands in the
        // built worker bundle for Wrangler to bind.
        const existingAlias = config.vite?.resolve?.alias ?? [];
        const aliasArray = Array.isArray(existingAlias)
          ? existingAlias.slice()
          : Object.entries(existingAlias).map(([find, replacement]) => ({ find, replacement }));

        const hasCloudflareAlias = aliasArray.some(
          (entry) => entry && entry.find === '@astrojs/cloudflare/entrypoints/server.js'
        );

        if (!hasCloudflareAlias) {
          aliasArray.push({
            find: '@astrojs/cloudflare/entrypoints/server.js',
            replacement: cloudflareServerAdapter,
          });
        }

        updateConfig({
          vite: {
            resolve: {
              alias: aliasArray,
            },
          },
        });

        addMiddleware({
          entrypoint: middlewareEntrypoint,
          order: 'pre',
        });

        const srcDirUrl = config.srcDir ?? config.root;
        const pagesDirUrl = config.pagesDir ?? new URL('./pages/', srcDirUrl);
        const projectPagesDir = fileURLToPath(pagesDirUrl);

        for (const route of routes) {
          const entrypoint = resolvePackagePath(route.entrypoint);
          const relativeToPages = relative(projectPagesDir, entrypoint);
          const entrypointWithinPages =
            relativeToPages === '' || (!relativeToPages.startsWith('..') && !isAbsolute(relativeToPages));

          if (entrypointWithinPages) {
            continue;
          }

          injectRoute({ pattern: route.pattern, entrypoint });
        }
      },

      'astro:config:done'({ config, injectTypes, logger }) {
        injectTypes({ filename: 'astro-cloudflare-pds.d.ts', content: buildInjectedEnvTypes() });

        const adapterName = config.adapter?.name ?? 'unknown adapter';
        if (!adapterName.toLowerCase().includes('cloudflare')) {
          logger.warn(
            `[alteran] Expected a Cloudflare adapter. Found "${adapterName}". The PDS worker relies on Cloudflare runtime bindings.`
          );
        }
      },
    },
  };
}
