/**
 * Blob Reference Extraction Utilities
 *
 * Provides functions to extract blob CIDs from AT Protocol records.
 * Used during migration and for blob usage tracking.
 */

/**
 * Extract all blob CIDs from a record object
 *
 * @param obj - The record object to scan
 * @returns Set of blob CIDs found in the record
 */
export function extractBlobRefs(obj: any): Set<string> {
  const refs = new Set<string>();
  extractBlobRefsRecursive(obj, refs);
  return refs;
}

export type LegacyBlobRef = {
  cid: string;
  mimeType: string;
};

/**
 * Recursively extract blob CIDs from an object
 */
function extractBlobRefsRecursive(obj: any, refs: Set<string>): void {
  if (!obj || typeof obj !== 'object') return;

  // Check for blob reference pattern ($type: 'blob')
  // This is the ONLY correct way to identify blobs in AT Protocol
  if (obj.$type === 'blob' && obj.ref) {
    if (typeof obj.ref === 'object') {
      // Handle both IPLD link formats: {"$link": "..."} and {"/": "..."}
      const cid = obj.ref.$link || obj.ref['/'];
      if (cid && typeof cid === 'string') {
        refs.add(cid);
      }
    } else if (typeof obj.ref === 'string') {
      refs.add(obj.ref);
    }
    return; // Don't recurse into blob objects
  }

  // DO NOT extract $link or cid fields outside of $type: 'blob' - those are record references!

  // Recurse into nested objects and arrays
  if (Array.isArray(obj)) {
    for (const item of obj) {
      extractBlobRefsRecursive(item, refs);
    }
  } else {
    for (const value of Object.values(obj)) {
      extractBlobRefsRecursive(value, refs);
    }
  }
}

/**
 * Extract blob references from known Bluesky record types
 * This is more specific than the generic extractor and handles
 * common patterns in app.bsky.* records.
 */
export function extractBskyBlobRefs(record: any): Set<string> {
  const refs = new Set<string>();
  for (const ref of extractBskyLegacyBlobRefs(record)) {
    refs.add(ref.cid);
  }

  // Handle app.bsky.feed.post embeds
  if (record.embed) {
    extractBlobRefsRecursive(record.embed, refs);
  }

  // Handle app.bsky.actor.profile avatar and banner
  if (record.avatar) {
    extractBlobRefsRecursive(record.avatar, refs);
  }
  if (record.banner) {
    extractBlobRefsRecursive(record.banner, refs);
  }

  // Handle app.bsky.feed.generator avatar
  if (record.$type === 'app.bsky.feed.generator' && record.avatar) {
    extractBlobRefsRecursive(record.avatar, refs);
  }

  // Fallback to generic extraction for any other patterns
  extractBlobRefsRecursive(record, refs);

  return refs;
}

export function extractBskyLegacyBlobRefs(record: any): LegacyBlobRef[] {
  if (!record || typeof record !== 'object') return [];
  if (typeof record.$type !== 'string' || !record.$type.startsWith('app.bsky.')) return [];

  const refs = new Map<string, LegacyBlobRef>();
  extractLegacyBlobRefsRecursive(record, refs);
  return Array.from(refs.values());
}

function extractLegacyBlobRefsRecursive(obj: any, refs: Map<string, LegacyBlobRef>): void {
  if (!obj || typeof obj !== 'object') return;
  if (isLegacyBlobObject(obj)) {
    refs.set(obj.cid, { cid: obj.cid, mimeType: obj.mimeType });
    return;
  }
  if (obj.$type === 'blob') return;
  if (Array.isArray(obj)) {
    for (const item of obj) extractLegacyBlobRefsRecursive(item, refs);
    return;
  }
  for (const value of Object.values(obj)) extractLegacyBlobRefsRecursive(value, refs);
}

function isLegacyBlobObject(obj: any): obj is { cid: string; mimeType: string } {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return false;
  const keys = Object.keys(obj).sort();
  return keys.join('\0') === ['cid', 'mimeType'].join('\0') &&
    typeof obj.cid === 'string' &&
    typeof obj.mimeType === 'string';
}

/**
 * Convert blob references to R2 keys
 *
 * @param cids - Set of blob CIDs
 * @returns Array of R2 keys
 */
export function blobCidsToKeys(cids: Set<string>): string[] {
  return Array.from(cids).map(cid => `blobs/by-cid/${cid}`);
}
