/** Validate an incarnation captured by a trusted caller before asynchronous work. */
export function isSpaceOwnerIncarnation(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{32}$/.test(value);
}
