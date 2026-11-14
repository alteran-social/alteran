import { readBodyBounded } from '../util';

const MAX_OAUTH_FORM_BYTES = 1024 * 1024;
const MAX_OAUTH_FORM_CHUNKS = 16_384;

export async function readOAuthForm(request: Request): Promise<URLSearchParams> {
  const bytes = await readBodyBounded(request, MAX_OAUTH_FORM_BYTES, { maxChunks: MAX_OAUTH_FORM_CHUNKS });
  return new URLSearchParams(new TextDecoder().decode(bytes));
}
