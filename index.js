import { readFileSync } from 'node:fs';
import { isAbsolute, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { integrationRoutes } from './route-registry.js';

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

  const routes = integrationRoutes({ includeRootEndpoint, debugRoutes });

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

        const cloudflareAliasKeys = [
          '@astrojs/cloudflare/entrypoints/server',
          '@astrojs/cloudflare/entrypoints/server.js',
        ];
        const hasCloudflareAlias = aliasArray.some(
          (entry) => entry && cloudflareAliasKeys.includes(entry.find)
        );

        if (!hasCloudflareAlias) {
          for (const find of cloudflareAliasKeys) {
            aliasArray.push({ find, replacement: cloudflareServerAdapter });
          }
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
