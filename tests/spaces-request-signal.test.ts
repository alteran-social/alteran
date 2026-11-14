import { expect } from '@std/expect';
import { join } from 'node:path';
import { connect } from 'node:net';
import { once } from 'node:events';

// This test requires a workerd that implements enable_request_signal. The
// project's pinned 2025 runtime predates that flag.
Deno.test({
  name: 'client disconnect aborts both the incoming and Astro-normalized request',
  ignore: Deno.env.get('ALTERAN_LIVE_REQUEST_SIGNAL_TEST') !== '1',
  sanitizeOps: false,
  sanitizeResources: false,
  async fn() {
    const root = join(import.meta.dirname!, '..');
    const temp = await Deno.makeTempDir({ prefix: 'alteran-request-signal-' });
    const bundle = join(temp, 'worker.mjs'), config = join(temp, 'config.capnp');
    const build = await new Deno.Command(Deno.execPath(), {
      cwd: root,
      args: ['run', '-A', 'npm:esbuild@0.25.12', 'tests/fixtures/spaces-request-signal-worker.ts',
        '--bundle', '--format=esm', '--platform=browser', `--outfile=${bundle}`],
      stdout: 'piped', stderr: 'piped',
    }).output();
    if (!build.success) throw new Error(`Test Worker bundle failed: ${new TextDecoder().decode(build.stderr)}`);
    const listener = Deno.listen({ hostname: '127.0.0.1', port: 0 });
    const port = (listener.addr as Deno.NetAddr).port;
    listener.close();
    await Deno.writeTextFile(config, `using W = import "/workerd/workerd.capnp";
      const config :W.Config = (
        services = [(name = "test", worker = (modules = [(name = "worker.mjs", esModule = embed "worker.mjs")],
          compatibilityDate = "2025-09-27", compatibilityFlags = ["enable_request_signal"]))],
        sockets = [(name = "http", address = "127.0.0.1:${port}", http = (), service = "test")]
      );`);
    const binary = Deno.env.get('MINIFLARE_WORKERD_PATH');
    if (!binary) throw new Error('Set MINIFLARE_WORKERD_PATH to a recent workerd');
    const worker = new Deno.Command(binary, { args: ['serve', config], stdout: 'piped', stderr: 'piped' }).spawn();
    const base = `http://127.0.0.1:${port}`;
    try {
      await waitFor(async () => (await fetch(`${base}/status`).catch(() => null))?.ok === true);
      for (const origin of [undefined, 'https://client.example']) {
        const id = crypto.randomUUID();
        const client = connect({ host: '127.0.0.1', port });
        client.on('error', () => {});
        await once(client, 'connect');
        const originHeader = origin ? `Origin: ${origin}\r\n` : '';
        client.write(`GET /xrpc/com.atproto.space.getRecord?id=${id} HTTP/1.1\r\n` +
          `Host: 127.0.0.1:${port}\r\n${originHeader}Connection: close\r\n\r\n`);
        const status = async () => await (await fetch(`${base}/status?id=${id}`)).json() as
          { original: boolean; normalized: boolean } | null;
        await waitFor(async () => await status() !== null);
        client.resetAndDestroy();
        try {
          await waitFor(async () => {
            const value = await status();
            return value?.original === true && value.normalized === true;
          });
        } catch {
          throw new Error(`Disconnect was not propagated: ${JSON.stringify(await status())}`);
        }
        expect(await status()).toEqual({ original: true, normalized: true });
      }
    } finally {
      worker.kill('SIGTERM');
      await worker.status;
      await Deno.remove(temp, { recursive: true });
    }
  },
});

async function waitFor(predicate: () => Promise<boolean>) {
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    if (await predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error('Timed out waiting for workerd request state');
}
