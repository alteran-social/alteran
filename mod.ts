import type { AstroIntegration } from "npm:astro@^6.3.3";
import alteran from "./index.js";

export type PdsIntegrationOptions = {
  readonly debugRoutes?: boolean;
  readonly includeRootEndpoint?: boolean;
  readonly injectServerEntry?: boolean;
};

const alteranIntegration = alteran as (
  options?: PdsIntegrationOptions,
) => AstroIntegration;

export default alteranIntegration;
