import { parse, type ParseError } from 'npm:jsonc-parser@3.3.1';
import { join } from 'node:path';

/** Read the Worker compatibility settings used by the repository deployment. */
export async function readWranglerCompatibility(root: string): Promise<{
  compatibilityDate: string;
  compatibilityFlags: string[];
}> {
  const errors: ParseError[] = [];
  const value: unknown = parse(await Deno.readTextFile(join(root, 'wrangler.jsonc')), errors, {
    allowTrailingComma: true,
  });
  if (errors.length || !isRecord(value) || typeof value.compatibility_date !== 'string' ||
    !/^\d{4}-\d{2}-\d{2}$/.test(value.compatibility_date) || !validFlags(value.compatibility_flags) ||
    !value.compatibility_flags.includes('enable_request_signal') ||
    value.compatibility_flags.includes('disable_request_signal')) {
    throw new Error('Invalid Worker compatibility settings');
  }
  if (value.env !== undefined) {
    if (!isRecord(value.env)) throw new Error('Invalid Worker environments');
    for (const environment of Object.values(value.env)) {
      if (!isRecord(environment)) throw new Error('Invalid Worker environment');
      if (environment.compatibility_flags !== undefined &&
        (!validFlags(environment.compatibility_flags) || !environment.compatibility_flags.includes('enable_request_signal') ||
          environment.compatibility_flags.includes('disable_request_signal'))) {
        throw new Error('Worker environment disables request signals');
      }
    }
  }
  return { compatibilityDate: value.compatibility_date, compatibilityFlags: value.compatibility_flags };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function validFlags(value: unknown): value is string[] {
  return Array.isArray(value) && value.length <= 64 &&
    value.every((flag) => typeof flag === 'string' && /^[a-z0-9_]{1,128}$/.test(flag));
}
