import { createPdsFetchHandler } from '../../src/worker/runtime';
import type { Env } from '../../src/env';

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const mode = request.headers.get('x-test-mode');
    let changed: unknown = env;
    if (mode === 'secret-throws') {
      changed = { ...env, PDS_DID: { get: () => { throw new Error('private-entry-secret'); } } };
    } else if (mode === 'invalid-config') {
      changed = { ...env, PDS_DID: '' };
    } else if (mode === 'seed-throws') {
      changed = { ...env, PDS_DID: 'did:example:seedfailure' };
    }
    return await createPdsFetchHandler()(request as never, changed as Env, ctx as never) as unknown as Response;
  },
};
