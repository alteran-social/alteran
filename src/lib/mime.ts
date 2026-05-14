export function mimeMatches(accept: string, mimeType: string): boolean {
  const normalizedAccept = accept.toLowerCase();
  const normalizedMime = mimeType.toLowerCase();
  if (normalizedAccept === '*/*') return true;
  if (normalizedAccept.endsWith('/*')) {
    return normalizedMime.startsWith(normalizedAccept.slice(0, -1));
  }
  return normalizedAccept === normalizedMime;
}
