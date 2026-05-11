import type { SSRManifest } from 'astro';
import { createPdsFetchHandler } from '../worker/runtime';
import { Sequencer } from '../worker/sequencer';

export function createExports(manifest: SSRManifest) {
  const fetch = createPdsFetchHandler({ manifest });
  return {
    default: { fetch },
    Sequencer,
  };
}

export { Sequencer };
