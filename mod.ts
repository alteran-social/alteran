import type { AstroIntegration } from "npm:astro@^6.3.3";
import type { PdsIntegrationOptions } from "./index.d.ts";
import alteran from "./index.js";

export type { Env, PdsIntegrationOptions, PdsLocals } from "./index.d.ts";

const alteranIntegration = alteran as (
  options?: PdsIntegrationOptions,
) => AstroIntegration;

export default alteranIntegration;
