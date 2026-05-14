import { lexicons } from '@atproto/api';
import { ensureValidDatetime } from '@atproto/syntax';
import { mimeMatches } from './mime';
import { RepoWriteError } from './repo-write-error';

type LexNode = Record<string, unknown>;

const MAX_SCHEMA_DEPTH = 100;

export function enforceRepoWriteLexiconConstraints(
  recordDef: Record<string, unknown>,
  record: Record<string, unknown>,
): void {
  const schema = asNode(recordDef.record);
  if (!schema) return;
  enforceNode(schema, record, 'record', 0);
}

function enforceNode(
  node: LexNode,
  value: unknown,
  path: string,
  depth: number,
): void {
  if (depth > MAX_SCHEMA_DEPTH) {
    throw new RepoWriteError('InvalidRequest', 'record schema is too deeply nested');
  }

  const type = node.type;
  if (type === 'ref') {
    const ref = typeof node.ref === 'string' ? node.ref : null;
    const target = ref ? asNode(lexicons.getDef(ref)) : null;
    if (target) enforceNode(target, value, path, depth + 1);
    return;
  }

  if (type === 'union') {
    enforceUnionNode(node, value, path, depth);
    return;
  }

  if (type === 'object') {
    enforceObjectNode(node, value, path, depth);
    return;
  }

  if (type === 'array') {
    const items = asNode(node.items);
    if (items && Array.isArray(value)) {
      for (let index = 0; index < value.length; index++) {
        enforceNode(items, value[index], `${path}/${index}`, depth + 1);
      }
    }
    return;
  }

  if (type === 'blob') {
    enforceBlobNode(node, value, path);
    return;
  }

  if (type === 'string' && node.format === 'datetime' && typeof value === 'string') {
    try {
      ensureValidDatetime(value);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'invalid datetime';
      throw new RepoWriteError('InvalidRequest', `${path} ${message}`);
    }
  }
}

function enforceObjectNode(
  node: LexNode,
  value: unknown,
  path: string,
  depth: number,
): void {
  if (!isRecord(value)) return;
  const properties = asNode(node.properties);
  if (!properties) return;

  for (const [key, child] of Object.entries(properties)) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) continue;
    const childNode = asNode(child);
    if (childNode) enforceNode(childNode, value[key], `${path}/${key}`, depth + 1);
  }
}

function enforceUnionNode(
  node: LexNode,
  value: unknown,
  path: string,
  depth: number,
): void {
  if (!isRecord(value) || typeof value.$type !== 'string') return;
  const refs = Array.isArray(node.refs) ? node.refs : [];
  for (const refValue of refs) {
    if (typeof refValue !== 'string' || !refMatchesType(refValue, value.$type)) continue;
    const target = asNode(lexicons.getDef(refValue));
    if (target) enforceNode(target, value, path, depth + 1);
    return;
  }
}

function enforceBlobNode(node: LexNode, value: unknown, path: string): void {
  if (!isRecord(value) || value.$type !== 'blob') return;
  const mimeType = typeof value.mimeType === 'string' ? value.mimeType : '';
  const size = typeof value.size === 'number' ? value.size : Number.NaN;
  const accept = strings(node.accept);
  if (accept.length > 0 && !accept.some((candidate) => mimeMatches(candidate, mimeType))) {
    throw new RepoWriteError('InvalidMimeType', `${path} blob mime type is not accepted`);
  }
  if (typeof node.maxSize === 'number' && Number.isFinite(size) && size > node.maxSize) {
    throw new RepoWriteError('BlobTooLarge', `${path} blob exceeds maxSize`, 413);
  }
}

function refMatchesType(ref: string, type: string): boolean {
  const refUri = toLexUri(ref);
  const typeUri = toLexUri(type);
  if (refUri === typeUri) return true;
  if (typeUri.endsWith('#main')) return refUri === typeUri.slice(0, -5);
  if (!typeUri.includes('#')) return refUri === `${typeUri}#main`;
  return false;
}

function toLexUri(value: string): string {
  return value.startsWith('lex:') ? value : `lex:${value}`;
}

function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : [];
}

function asNode(value: unknown): LexNode | null {
  return isRecord(value) ? value : null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}
