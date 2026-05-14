import type { AstroIntegration } from 'astro';
import type { Env, PdsLocals } from './types/public-env';

export interface PdsIntegrationOptions {
  debugRoutes?: boolean;
  includeRootEndpoint?: boolean;
  injectServerEntry?: boolean;
}

export default function alteran(options?: PdsIntegrationOptions): AstroIntegration;

export type { Env, PdsLocals };
