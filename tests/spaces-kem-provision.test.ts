import { expect } from '@std/expect';
import { join } from 'node:path';
import { describe, it } from './helpers/bdd';
import { createSpaceKemFile, localFiles, readSpaceKemPublicKey } from '../scripts/space-kem-files';
import { loadSpaceKemKey } from '../src/lib/spaces/kem-key';
import type { Env } from '../src/env';

const script = new URL('../scripts/space-kem-key.ts', import.meta.url).pathname;
const decoder = new TextDecoder();

async function temporary<T>(action: (directory: string) => Promise<T>): Promise<T> {
  const directory = await Deno.makeTempDir({ prefix: 'alteran-kem-provision-' });
  try { return await action(directory); } finally { await Deno.remove(directory, { recursive: true }); }
}

function run(action: string, path: string) {
  return new Deno.Command(Deno.execPath(), {
    args: ['run', '--allow-read', '--allow-write', '--allow-sys=uid', script, action, path],
    stdout: 'piped', stderr: 'piped',
  }).output();
}

describe('local Space KEM provisioning', () => {
  it('creates a private key, prints only its public identity and recovers it later', async () => {
    await temporary(async (directory) => {
      const path = join(directory, 'kem.key');
      const created = await run('create', path);
      expect(created.success).toBe(true);
      const publicKey = decoder.decode(created.stdout).trim();
      expect(publicKey).toMatch(/^did:key:zDna[a-zA-Z0-9]+$/);
      const privateText = await Deno.readTextFile(path);
      expect(/^[0-9a-f]{64}\n$/.test(privateText)).toBe(true);
      expect(decoder.decode(created.stdout).includes(privateText.trim())).toBe(false);
      expect(decoder.decode(created.stderr).includes(privateText.trim())).toBe(false);
      const stat = await Deno.stat(path);
      expect((stat.mode ?? 0) & 0o777).toBe(0o600);
      expect(stat.nlink).toBe(1);
      const loaded = await loadSpaceKemKey({ PDS_SPACE_KEM_KEY: privateText } as Env);
      expect(loaded.tag).toBe('ready');
      if (loaded.tag !== 'ready') throw new Error('Generated key could not be loaded');
      expect(loaded.key.publicDidKey).toBe(publicKey);
      const recovered = await run('public', path);
      expect(recovered.success).toBe(true);
      expect(decoder.decode(recovered.stdout).trim()).toBe(publicKey);
      expect(decoder.decode(recovered.stderr).includes(privateText.trim())).toBe(false);
    });
  });

  it('never replaces an existing file or a symlink', async () => {
    await temporary(async (directory) => {
      const existing = join(directory, 'existing');
      await Deno.writeTextFile(existing, 'sentinel', { createNew: true, mode: 0o600 });
      await expect(createSpaceKemFile(existing)).rejects.toThrow();
      expect(await Deno.readTextFile(existing)).toBe('sentinel');
      for (const target of [existing, join(directory, 'missing')]) {
        const link = join(directory, target === existing ? 'link' : 'dangling');
        await Deno.symlink(target, link);
        await expect(createSpaceKemFile(link)).rejects.toThrow();
        await expect(readSpaceKemPublicKey(link)).rejects.toThrow();
        expect((await Deno.lstat(link)).isSymlink).toBe(true);
      }
      expect(await Deno.readTextFile(existing)).toBe('sentinel');
    });
  });

  it('rejects unprotected directories, Git worktrees and unsupported ownership', async () => {
    await temporary(async (directory) => {
      const publicDirectory = join(directory, 'public');
      await Deno.mkdir(publicDirectory, { mode: 0o755 });
      await Deno.chmod(publicDirectory, 0o755);
      await expect(createSpaceKemFile(join(publicDirectory, 'key'))).rejects.toThrow();
      const worktree = join(directory, 'repo');
      await Deno.mkdir(worktree, { mode: 0o700 });
      await Deno.mkdir(join(worktree, '.git'), { mode: 0o700 });
      await Deno.writeTextFile(join(worktree, '.git', 'HEAD'), 'ref: refs/heads/main\n');
      await expect(createSpaceKemFile(join(worktree, 'key'))).rejects.toThrow();
      await expect(createSpaceKemFile(join(directory, 'other'), { ...localFiles, uid: () => null })).rejects.toThrow();
    });
  });

  it('allows exactly one of two concurrent creators', async () => {
    await temporary(async (directory) => {
      const path = join(directory, 'key');
      const results = await Promise.all([run('create', path), run('create', path)]);
      const success = results.filter((entry) => entry.success);
      expect(success).toHaveLength(1);
      expect(await readSpaceKemPublicKey(path)).toBe(decoder.decode(success[0].stdout).trim());
    });
  });

  it('fails promptly if a cooperating process holds the key lock', async () => {
    await temporary(async (directory) => {
      const path = join(directory, 'locked');
      await createSpaceKemFile(path);
      const lock = await Deno.open(path, { read: true });
      const child = new Deno.Command(Deno.execPath(), {
        args: ['run', '--allow-read', '--allow-write', '--allow-sys=uid', script, 'public', path],
        stdout: 'piped', stderr: 'piped',
      });
      try {
        expect(await lock.tryLock(true)).toBe(true);
        const process = child.spawn();
        let timeout: ReturnType<typeof setTimeout> | undefined;
        const output = await Promise.race([
          process.output(),
          new Promise<null>((resolve) => { timeout = setTimeout(() => resolve(null), 5000); }),
        ]);
        if (timeout !== undefined) clearTimeout(timeout);
        if (!output) {
          process.kill('SIGTERM');
          await process.status;
          throw new Error('A locked key caused the utility to wait');
        }
        expect(output.success).toBe(false);
        expect(decoder.decode(output.stdout)).toBe('');
      } finally {
        lock.close();
      }
    });
  });

  it('detects a concurrent same-inode rewrite even when timestamps match', async () => {
    await temporary(async (directory) => {
      const path = join(directory, 'first');
      const other = join(directory, 'second');
      const first = await createSpaceKemFile(path);
      const second = await createSpaceKemFile(other);
      expect(first === second).toBe(false);
      const replacement = await Deno.readTextFile(other);
      const fixed = new Date('2026-01-01T00:00:00Z');
      const timestamp = (info: Deno.FileInfo): Deno.FileInfo => ({ ...info, mtime: fixed, ctime: fixed });
      let replaced = false;
      const files: typeof localFiles = {
        ...localFiles,
        async lstat(name) {
          const info = await localFiles.lstat(name);
          return name === path ? timestamp(info) : info;
        },
        async open(name, options) {
          const file = await localFiles.open(name, options);
          if (name !== path) return file;
          return new Proxy(file, {
            get(target, property) {
              if (property === 'stat') return async () => timestamp(await target.stat());
              if (property === 'read') return async (bytes: Uint8Array) => {
                const count = await target.read(bytes);
                if (count !== null && !replaced) {
                  replaced = true;
                  await Deno.writeTextFile(path, replacement);
                }
                return count;
              };
              const value = Reflect.get(target, property, target);
              return typeof value === 'function' ? value.bind(target) : value;
            },
          });
        },
      };
      await expect(readSpaceKemPublicKey(path, files)).rejects.toThrow();
      expect(replaced).toBe(true);
      expect(await readSpaceKemPublicKey(path)).toBe(second);
    });
  });

  it('handles short writes and fails closed on write, sync or readback errors', async () => {
    await temporary(async (directory) => {
      const shortPath = join(directory, 'short');
      const key = await createSpaceKemFile(shortPath, faultFiles(shortPath, directory, 'short-write'));
      expect(await readSpaceKemPublicKey(shortPath)).toBe(key);
      for (const fault of ['zero-write', 'file-sync', 'dir-sync', 'readback', 'invalid-key'] as const) {
        const path = join(directory, fault);
        await expect(createSpaceKemFile(path, faultFiles(path, directory, fault))).rejects.toThrow();
        expect((await Deno.lstat(path)).isFile).toBe(true);
        await expect(createSpaceKemFile(path)).rejects.toThrow();
        if (fault === 'dir-sync') expect(await readSpaceKemPublicKey(path)).toMatch(/^did:key:/);
      }
    });
  });

  it('rejects invalid, oversized, linked or exposed existing key files', async () => {
    await temporary(async (directory) => {
      const invalid = join(directory, 'invalid');
      await Deno.writeTextFile(invalid, '0'.repeat(64) + '\n', { mode: 0o600 });
      await expect(readSpaceKemPublicKey(invalid)).rejects.toThrow();
      await Deno.writeTextFile(invalid, 'a'.repeat(66));
      await expect(readSpaceKemPublicKey(invalid)).rejects.toThrow();
      const valid = join(directory, 'valid');
      await createSpaceKemFile(valid);
      const linked = join(directory, 'hardlink');
      await Deno.link(valid, linked);
      await expect(readSpaceKemPublicKey(valid)).rejects.toThrow();
      await Deno.remove(linked);
      await Deno.chmod(valid, 0o400);
      expect(await readSpaceKemPublicKey(valid)).toMatch(/^did:key:/);
      await Deno.chmod(valid, 0o644);
      await expect(readSpaceKemPublicKey(valid)).rejects.toThrow();
    });
  });
});

type Fault = 'short-write' | 'zero-write' | 'file-sync' | 'dir-sync' | 'readback' | 'invalid-key';

function faultFiles(path: string, directory: string, fault: Fault): typeof localFiles {
  return {
    ...localFiles,
    async open(name, options) {
      const file = await localFiles.open(name, options);
      return new Proxy(file, {
        get(target, property) {
          if (name === path && property === 'write' && fault === 'short-write') {
            return (bytes: Uint8Array) => target.write(bytes.subarray(0, Math.min(3, bytes.length)));
          }
          if (name === path && property === 'write' && fault === 'zero-write') return async () => 0;
          if (property === 'sync' && ((name === path && fault === 'file-sync') ||
            (name === directory && fault === 'dir-sync'))) return async () => { throw new Error('Injected sync failure'); };
          if (name === path && property === 'read' && fault === 'readback') {
            return async () => { throw new Error('Injected read failure'); };
          }
          if (name === path && property === 'read' && fault === 'invalid-key') {
            return async (bytes: Uint8Array) => {
              const count = await target.read(bytes);
              if (count !== null) bytes.fill(0, 0, count);
              return count;
            };
          }
          const value = Reflect.get(target, property, target);
          return typeof value === 'function' ? value.bind(target) : value;
        },
      });
    },
  };
}
