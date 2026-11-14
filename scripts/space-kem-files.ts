import { dirname, basename, join, resolve } from 'node:path';
import { P256Keypair } from '@atproto/crypto-spaces';
import { encapsulate } from '@atproto/space';
import type { Env } from '../src/env';
import { loadSpaceKemKey } from '../src/lib/spaces/kem-key';

type FileOps = {
  readonly open: (path: string, options: Deno.OpenOptions) => Promise<Deno.FsFile>;
  readonly lstat: (path: string) => Promise<Deno.FileInfo>;
  readonly realPath: (path: string) => Promise<string>;
  readonly uid: () => number | null;
};

export const localFiles: FileOps = {
  open: (path, options) => Deno.open(path, options),
  lstat: (path) => Deno.lstat(path),
  realPath: (path) => Deno.realPath(path),
  uid: () => Deno.uid(),
};

type Destination = {
  readonly path: string;
  readonly directory: string;
  readonly directoryInfo: Deno.FileInfo;
  readonly uid: number;
};

/** Create one local key without replacing an existing file. */
export async function createSpaceKemFile(input: string, files: FileOps = localFiles): Promise<string> {
  const destination = await prepareDestination(input, files);
  const pair = await P256Keypair.create({ exportable: true });
  const privateBytes = await pair.export();
  let encoded = new Uint8Array();
  let file: Deno.FsFile | undefined;
  let directory: Deno.FsFile | undefined;
  try {
    if (privateBytes.length !== 32) throw new Error('Invalid generated key');
    const hex = Array.from(privateBytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
    encoded = new TextEncoder().encode(`${hex}\n`);
    directory = await openDirectory(destination, files);
    file = await files.open(destination.path, { read: true, write: true, createNew: true, mode: 0o600 });
    if (!await file.tryLock(true)) throw new Error('Key file is locked');
    const opened = await file.stat();
    if (!privateFile(opened, destination.uid) || opened.size !== 0) throw new Error('Invalid key file');
    await assertDirectory(destination, directory, files);
    await writeAll(file, encoded);
    await file.sync();
    const verified = await verifyOpenFile(file, destination, files, pair.did());
    await directory.sync();
    await assertDirectory(destination, directory, files);
    await assertUnchangedFile(file, destination, files, verified.info);
    const confirmed = await verifyOpenFile(file, destination, files, verified.publicKey);
    await assertUnchangedFile(file, destination, files, confirmed.info);
    return confirmed.publicKey;
  } finally {
    encoded.fill(0);
    privateBytes.fill(0);
    file?.close();
    directory?.close();
  }
}

/** Recover the public key from an existing private file without modifying it. */
export async function readSpaceKemPublicKey(input: string, files: FileOps = localFiles): Promise<string> {
  const destination = await prepareDestination(input, files);
  const before = await files.lstat(destination.path);
  if (!privateFile(before, destination.uid)) throw new Error('Invalid key file');
  const directory = await openDirectory(destination, files);
  let file: Deno.FsFile | undefined;
  try {
    file = await files.open(destination.path, { read: true });
    if (!await file.tryLock(true)) throw new Error('Key file is locked');
    if (!sameFile(before, await file.stat())) throw new Error('Key file changed');
    await assertDirectory(destination, directory, files);
    await file.sync();
    const verified = await verifyOpenFile(file, destination, files);
    await directory.sync();
    await assertDirectory(destination, directory, files);
    await assertUnchangedFile(file, destination, files, verified.info);
    const confirmed = await verifyOpenFile(file, destination, files, verified.publicKey);
    await assertUnchangedFile(file, destination, files, confirmed.info);
    return confirmed.publicKey;
  } finally {
    file?.close();
    directory.close();
  }
}

async function prepareDestination(input: string, files: FileOps): Promise<Destination> {
  if (Deno.build.os !== 'linux' || typeof input !== 'string' || !input || input.length > 4096 ||
    input.includes('\0') || input.endsWith('/')) throw new Error('Invalid destination');
  const uid = files.uid();
  if (uid === null || !Number.isSafeInteger(uid) || uid < 0) throw new Error('Unsupported filesystem');
  const absolute = resolve(input);
  const name = basename(absolute);
  if (name === '.' || name === '..') throw new Error('Invalid destination');
  const directory = await files.realPath(dirname(absolute));
  const directoryInfo = await files.lstat(directory);
  if (!privateDirectory(directoryInfo, uid)) throw new Error('Directory is not private');
  for (let current = directory;; current = dirname(current)) {
    try {
      const marker = join(current, '.git');
      const entry = await files.lstat(marker);
      if (entry.isDirectory) await files.lstat(join(marker, 'HEAD'));
      throw new Error('Key files must be outside a Git worktree');
    } catch (error) {
      if (!(error instanceof Deno.errors.NotFound)) throw error;
    }
    if (dirname(current) === current) break;
  }
  return { path: join(directory, name), directory, directoryInfo, uid };
}

async function openDirectory(destination: Destination, files: FileOps): Promise<Deno.FsFile> {
  const directory = await files.open(destination.directory, { read: true });
  try {
    await assertDirectory(destination, directory, files);
    return directory;
  } catch (error) {
    directory.close();
    throw error;
  }
}

async function assertDirectory(destination: Destination, opened: Deno.FsFile, files: FileOps): Promise<void> {
  const byHandle = await opened.stat();
  const byName = await files.lstat(destination.directory);
  if (!privateDirectory(byHandle, destination.uid) || !privateDirectory(byName, destination.uid) ||
    !sameFile(destination.directoryInfo, byHandle) || !sameFile(byHandle, byName)) throw new Error('Directory changed');
}

async function writeAll(file: Deno.FsFile, bytes: Uint8Array): Promise<void> {
  let offset = 0;
  while (offset < bytes.length) {
    const written = await file.write(bytes.subarray(offset));
    if (!Number.isSafeInteger(written) || written <= 0 || written > bytes.length - offset) throw new Error('Key write failed');
    offset += written;
  }
}

async function verifyOpenFile(
  file: Deno.FsFile, destination: Destination, files: FileOps, expected?: string,
): Promise<{ readonly publicKey: string; readonly info: Deno.FileInfo }> {
  const before = await file.stat();
  if (!privateFile(before, destination.uid) || before.size !== 65) throw new Error('Invalid key file');
  await file.seek(0, Deno.SeekMode.Start);
  const bytes = new Uint8Array(66);
  let length = 0;
  try {
    while (length < bytes.length) {
      const read = await file.read(bytes.subarray(length));
      if (read === null) break;
      if (!Number.isSafeInteger(read) || read <= 0 || read > bytes.length - length) throw new Error('Key read failed');
      length += read;
    }
    if (length !== 65) throw new Error('Invalid key file');
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, length));
    if (!/^[0-9a-f]{64}\n$/.test(text)) throw new Error('Invalid key file');
    const loaded = await loadSpaceKemKey({ PDS_SPACE_KEM_KEY: text } as Env);
    if (loaded.tag !== 'ready' || (expected !== undefined && loaded.key.publicDidKey !== expected)) {
      throw new Error('Key verification failed');
    }
    const shared = await encapsulate(loaded.key.publicDidKey as `did:${string}:${string}`);
    const derived = loaded.key.deriveSharedSecret(shared.keyShare);
    try {
      if (derived.length !== shared.sharedSecret.length || !derived.every((byte, index) => byte === shared.sharedSecret[index])) {
        throw new Error('Key verification failed');
      }
    } finally {
      derived.fill(0);
      shared.sharedSecret.fill(0);
    }
    const info = await assertUnchangedFile(file, destination, files, before);
    return { publicKey: loaded.key.publicDidKey, info };
  } finally {
    bytes.fill(0);
  }
}

async function assertUnchangedFile(
  file: Deno.FsFile, destination: Destination, files: FileOps, expected: Deno.FileInfo,
): Promise<Deno.FileInfo> {
  const byHandle = await file.stat();
  const byName = await files.lstat(destination.path);
  if (!privateFile(byHandle, destination.uid) || !privateFile(byName, destination.uid) ||
    !sameFile(expected, byHandle) || !sameFile(byHandle, byName) || byHandle.size !== 65 || byName.size !== 65 ||
    !sameTimestamp(expected.mtime, byHandle.mtime) || !sameTimestamp(expected.ctime, byHandle.ctime) ||
    !sameTimestamp(byHandle.mtime, byName.mtime) || !sameTimestamp(byHandle.ctime, byName.ctime)) {
    throw new Error('Key file changed');
  }
  return byHandle;
}

function privateDirectory(info: Deno.FileInfo, uid: number): boolean {
  return info.isDirectory && info.uid === uid && info.mode !== null && (info.mode & 0o7777) === 0o700 &&
    info.dev !== null && info.ino !== null;
}

function privateFile(info: Deno.FileInfo, uid: number): boolean {
  return info.isFile && !info.isSymlink && info.uid === uid && info.mode !== null &&
    (info.mode & 0o7077) === 0 && (info.mode & 0o400) !== 0 && info.nlink === 1 &&
    info.dev !== null && info.ino !== null;
}

function sameFile(first: Deno.FileInfo, second: Deno.FileInfo): boolean {
  return first.dev !== null && first.ino !== null && first.dev === second.dev && first.ino === second.ino;
}

function sameTimestamp(first: Date | null, second: Date | null): boolean {
  return first !== null && second !== null && first.getTime() === second.getTime();
}
