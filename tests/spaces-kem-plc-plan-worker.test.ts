import { expect } from '@std/expect';
import { P256Keypair, Secp256k1Keypair } from '@atproto/crypto-spaces';
import { createOp } from '@did-plc/lib';
import { Miniflare } from 'miniflare';
import { join } from 'node:path';
import { planKemPlcUpdate } from '../src/lib/spaces/kem-plc-plan';

Deno.test({
  name: 'unsigned KEM planner works in the configured Worker runtime',
  sanitizeOps: false,
  sanitizeResources: false,
  async fn() {
    const root = join(import.meta.dirname!, '..');
    const directory = await Deno.makeTempDir({ prefix: 'alteran-kem-plc-worker-' });
    const bundle = join(directory, 'worker.mjs');
    const build = await new Deno.Command(Deno.execPath(), {
      cwd: root,
      args: ['run', '-A', 'npm:esbuild@0.25.12', 'tests/fixtures/kem-plc-planner-worker.ts',
        '--bundle', '--format=esm', '--platform=browser', '--external:node:*', `--outfile=${bundle}`],
      stdout: 'piped', stderr: 'piped',
    }).output();
    if (!build.success) throw new Error('Planner Worker bundle failed');
    const worker = new Miniflare({ modules: true, modulesRoot: directory, scriptPath: bundle,
      compatibilityDate: '2025-09-27', compatibilityFlags: ['nodejs_compat'] });
    try {
      const signing = await Secp256k1Keypair.create();
      const recovery = await Secp256k1Keypair.create();
      const kem = await P256Keypair.create();
      const genesis = await createOp({ signingKey: signing.did(), rotationKeys: [recovery.did(), signing.did()],
        handle: 'worker-planner.test', pds: 'https://pds.example', signer: signing });
      const input = [JSON.stringify(genesis.op), genesis.did, '1234567890abcdef1234567890abcdef', true,
        'https://pds.example', signing.did(), signing.did(), kem.did()] as const;
      const expected = planKemPlcUpdate(...input);
      expect(expected.tag).toBe('proposed');
      const response = await worker.dispatchFetch('https://pds.example/', {
        method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(input),
      });
      expect(response.status).toBe(200);
      expect(await response.json()).toEqual(JSON.parse(JSON.stringify(expected)));
    } finally {
      await worker.dispose();
      await Deno.remove(directory, { recursive: true });
    }
  },
});
