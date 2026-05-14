import { CID } from 'multiformats/cid';
import type { RepoOp } from '../../lib/firehose/frames';

export function reviveCid(value: unknown): CID | null {
  try {
    if (value == null) return null;
    const asCid = (CID as unknown as { asCID?: (v: unknown) => CID | null }).asCID?.(value);
    if (asCid) return asCid;
    if (typeof value === 'string') return CID.parse(value);
    if (value && typeof value === 'object' && '/' in value) {
      const link = (value as { '/'?: unknown })['/'];
      if (typeof link === 'string') return CID.parse(link);
    }
  } catch {
    // Fall through: caller treats null as unknown CID.
  }
  return null;
}

export function reviveOps(ops: unknown): RepoOp[] | undefined {
  if (!Array.isArray(ops)) return undefined;
  return ops.map((raw) => {
    const op = raw as { action: RepoOp['action']; path: string; cid?: unknown; prev?: unknown };
    const prev = op.prev != null ? reviveCid(op.prev) ?? undefined : undefined;
    return {
      action: op.action,
      path: op.path,
      cid: reviveCid(op.cid),
      ...(prev ? { prev } : {}),
    };
  });
}

export function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}
