/** Merge comma-separated field names without losing existing casing or entries. */
export function mergeHeaderTokens(headers: Headers, field: string, additions: readonly string[]): void {
  const values = new Map<string, string>();
  for (const item of (headers.get(field) ?? '').split(',')) {
    const name = item.trim();
    if (name) values.set(name.toLowerCase(), name);
  }
  if (field.toLowerCase() === 'vary' && values.has('*')) return;
  for (const name of additions) {
    if (!values.has(name.toLowerCase())) values.set(name.toLowerCase(), name);
  }
  if (values.size) headers.set(field, Array.from(values.values()).join(', '));
}
