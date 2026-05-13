import type { AuthAccessContext } from './auth-scope';

export const APP_PASSWORD_RESTRICTED_PREFERENCE_TYPES = new Set([
  'app.bsky.actor.defs#personalDetailsPref',
  'app.bsky.actor.defs#bskyAppStatePref',
]);

function preferenceType(value: unknown): string | null {
  if (!value || typeof value !== 'object') return null;
  const type = (value as { $type?: unknown }).$type;
  return typeof type === 'string' ? type : null;
}

export function isAppPasswordRestrictedPreference(value: unknown): boolean {
  const type = preferenceType(value);
  return !!type && APP_PASSWORD_RESTRICTED_PREFERENCE_TYPES.has(type);
}

export function preferencesForAccess(
  preferences: unknown[],
  access: AuthAccessContext,
): unknown[] {
  if (!access.isAppPassword) return preferences;
  return preferences.filter((pref) => !isAppPasswordRestrictedPreference(pref));
}

export function hasAppPasswordRestrictedPreferences(
  preferences: unknown[],
  access: AuthAccessContext,
): boolean {
  return access.isAppPassword && preferences.some(isAppPasswordRestrictedPreference);
}

export function preferencesForWrite(
  existingPreferences: unknown[],
  nextPreferences: unknown[],
  access: AuthAccessContext,
): unknown[] {
  if (!access.isAppPassword) return nextPreferences;
  const preserved = existingPreferences.filter(isAppPasswordRestrictedPreference);
  return [
    ...nextPreferences.filter((pref) => !isAppPasswordRestrictedPreference(pref)),
    ...preserved,
  ];
}
