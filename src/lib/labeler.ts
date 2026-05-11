import type { Env } from '../env';
import { getRecord } from '../db/dal';
import { buildProfileView, getPrimaryActor } from './actor';

export interface LabelerViewOptions {
  detailed?: boolean;
}

interface LabelerView {
  uri: string;
  cid: string;
  creator: ReturnType<typeof buildProfileView>;
  indexedAt: string;
  likeCount: number;
  viewer: Record<string, unknown>;
  labels?: unknown;
  policies?: { labelValues: unknown[]; labelValueDefinitions?: unknown[] };
  reasonTypes?: unknown[];
  subjectTypes?: unknown[];
  subjectCollections?: unknown[];
}

const LABELER_COLLECTION = 'app.bsky.labeler.service';
const LABELER_RKEY = 'self';

export async function getLabelerServiceViews(
  env: Env,
  dids: string[],
  options: LabelerViewOptions = {},
): Promise<LabelerView[]> {
  const detailed = options.detailed ?? false;
  const primaryActor = await getPrimaryActor(env);

  const unique = Array.from(new Set(dids.map((did) => did.trim()).filter(Boolean)));
  const views: LabelerView[] = [];

  for (const did of unique) {
    // Single-user PDS only has local labeler data.
    if (did !== primaryActor.did) continue;

    const uri = `at://${did}/${LABELER_COLLECTION}/${LABELER_RKEY}`;
    const row = await getRecord(env, uri);
    if (!row || !row.json) continue;

    let parsedRecord: Record<string, unknown>;
    try {
      const parsed = JSON.parse(row.json);
      if (typeof parsed !== 'object' || parsed === null) continue;
      parsedRecord = parsed as Record<string, unknown>;
    } catch {
      continue;
    }

    const indexedAt =
      typeof parsedRecord.createdAt === 'string' ? parsedRecord.createdAt : new Date().toISOString();
    const baseView: LabelerView = {
      uri,
      cid: row.cid,
      creator: buildProfileView(primaryActor),
      indexedAt,
      likeCount: 0,
      viewer: {},
    };

    if (detailed) {
      views.push({
        ...baseView,
        policies: normalizePolicies(parsedRecord.policies),
        reasonTypes: Array.isArray(parsedRecord.reasonTypes) ? parsedRecord.reasonTypes : undefined,
        subjectTypes: Array.isArray(parsedRecord.subjectTypes) ? parsedRecord.subjectTypes : undefined,
        subjectCollections: Array.isArray(parsedRecord.subjectCollections)
          ? parsedRecord.subjectCollections
          : undefined,
        labels: extractLabels(parsedRecord.labels),
      });
    } else {
      const labels = extractLabels(parsedRecord.labels);
      if (labels) baseView.labels = labels;
      views.push(baseView);
    }
  }

  return views;
}

function normalizePolicies(input: unknown): LabelerView['policies'] {
  if (input && typeof input === 'object' && !Array.isArray(input)) {
    const policies = input as { labelValues?: unknown; labelValueDefinitions?: unknown };
    return {
      labelValues: Array.isArray(policies.labelValues) ? policies.labelValues : [],
      labelValueDefinitions: Array.isArray(policies.labelValueDefinitions)
        ? policies.labelValueDefinitions
        : undefined,
    };
  }
  return { labelValues: [] };
}

function extractLabels(input: unknown): unknown {
  if (!input) return undefined;
  if (Array.isArray(input)) return input.length ? input : undefined;
  if (typeof input === 'object') return input;
  return undefined;
}
