import { readFileSync } from 'node:fs';
import { isAbsolute, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const CORE_ROUTES = [
  { pattern: '/.well-known/atproto-did', entrypoint: './src/pages/.well-known/atproto-did.ts' },
  { pattern: '/.well-known/did.json', entrypoint: './src/pages/.well-known/did.json.ts' },
  { pattern: '/health', entrypoint: './src/pages/health.ts' },
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
  { pattern: '/xrpc/com.atproto.server.createSession', entrypoint: './src/pages/xrpc/com.atproto.server.createSession.ts' },
  { pattern: '/xrpc/com.atproto.server.deleteSession', entrypoint: './src/pages/xrpc/com.atproto.server.deleteSession.ts' },
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

export default function alteran(options = {}) {
  const {
    debugRoutes = false,
    includeRootEndpoint = false,
    injectServerEntry = false,
  } = options;

  const middlewareEntrypoint = resolvePackagePath('./src/middleware.ts');
  const serverEntrypoint = resolvePackagePath('./src/_worker.ts');
  const cloudflareServerAdapter = resolvePackagePath('./src/entrypoints/server.ts');

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

        const vitePlugins = Array.isArray(config.vite?.plugins)
          ? config.vite.plugins.slice().filter(Boolean)
          : [];

        vitePlugins.push({
          name: 'alteran-sequencer-export',
          enforce: 'post',
          apply: 'build',
          transform(code, id) {
            if (code.includes("_exports['Sequencer']") || code.includes('_exports.Sequencer')) {
              return null;
            }

            // Astro 6: virtual:astro:legacy-ssr-entry — the resolved id is `\0virtual:astro:legacy-ssr-entry`.
            // The body is a thin wrapper that re-exports `_exports.default`; we tack on a named Sequencer export.
            if (id.includes('virtual:astro:legacy-ssr-entry')) {
              return {
                code: `${code}\nexport const Sequencer = _exports['Sequencer'];\n`,
                map: null,
              };
            }

            // Astro 5: @astrojs-ssr-virtual-entry — the body assigns `_exports` and exports a default; patch both.
            if (id.includes('@astrojs-ssr-virtual-entry')) {
              if (!code.includes('const _exports = createExports')) return null;
              const withSequencer = code.replace(
                'const __astrojsSsrVirtualEntry = _exports.default;',
                "const Sequencer = _exports['Sequencer'];\nconst __astrojsSsrVirtualEntry = _exports.default;",
              );
              if (withSequencer === code) return null;
              const reexported = withSequencer.replace(
                'export { __astrojsSsrVirtualEntry as default, pageMap };',
                'export { Sequencer, __astrojsSsrVirtualEntry as default, pageMap };',
              );
              return { code: reexported, map: null };
            }

            return null;
          },
        });

        updateConfig({
          vite: {
            resolve: {
              alias: aliasArray,
            },
            plugins: vitePlugins,
          },
        });

        if (injectServerEntry) {
          if (config.build?.serverEntry && config.build.serverEntry !== serverEntrypoint) {
            logger.info(
              '[alteran] Overriding existing build.serverEntry with the packaged worker entry. Pass { injectServerEntry: false } to opt out.'
            );
          }
          updateConfig({
            build: {
              serverEntry: serverEntrypoint,
            },
          });
        }

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
        const envTypesPath = resolvePackagePath('./types/env.d.ts');
        const envTypes = readFileSync(envTypesPath, 'utf-8');
        injectTypes({ filename: 'astro-cloudflare-pds.d.ts', content: envTypes });

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
