import { fork, ChildProcess } from 'node:child_process';
import getPort from 'get-port';

export interface AstroTestServer {
  port: number;
  url: string;
  proc: ChildProcess;
  stdout: string[];
  stderr: string[];
}

export async function startAstroDev(): Promise<AstroTestServer> {
  let port: number;
  try {
    port = await getPort();
  } catch {
    port = Number(process.env.TEST_PDS_PORT ?? 9900);
  }
  const proc = fork('./node_modules/astro/astro.js', ['dev', '--port', String(port)], {
    silent: true,
  });

  const stdout: string[] = [];
  const stderr: string[] = [];

  return await new Promise<AstroTestServer>((resolve, reject) => {
    let settled = false;
    const fail = (reason: string) => {
      if (settled) return;
      settled = true;
      if (!proc.killed) {
        proc.kill();
      }
      const details = [`reason=${reason}`];
      if (stdout.length) {
        details.push(`stdout=${stdout.join('')}`);
      }
      if (stderr.length) {
        details.push(`stderr=${stderr.join('')}`);
      }
      reject(new Error(`Astro dev server failed to start: ${details.join(' ')}`));
    };
    const startupTimeout = setTimeout(() => {
      fail('timeout');
    }, 30_000);

    proc.stdout?.on('data', (data: Buffer) => {
      const text = data.toString();
      stdout.push(text);
      if (text.includes('Server running')) {
        clearTimeout(startupTimeout);
        if (!settled) {
          settled = true;
          resolve({ port, url: `http://localhost:${port}`, proc, stdout, stderr });
        }
      }
    });

    proc.stderr?.on('data', (data: Buffer) => {
      const text = data.toString();
      stderr.push(text);
    });

    proc.once('exit', (code) => {
      clearTimeout(startupTimeout);
      if (!settled) {
        fail(`exit:${code}`);
      }
    });
  });
}

export async function stopAstroDev(server: AstroTestServer): Promise<void> {
  if (!server) return;
  if (server.proc.killed) return;

  await new Promise<void>((resolve) => {
    const timer = setTimeout(() => resolve(), 5_000);
    server.proc.once('exit', () => {
      clearTimeout(timer);
      resolve();
    });
    server.proc.kill();
  });
}
