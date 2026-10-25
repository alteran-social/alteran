const CHAT_METHOD_PREFIX = 'chat.bsky.';
const CREATE_ACCOUNT_METHOD = 'com.atproto.server.createaccount';

// NSID.isValid accepts any ASCII case, and the reference PDS matches lexicon
// methods case-insensitively (LxmPrefix / LxmSet). Folding here stops a
// mixed-case method from skipping the privileged or protected gate.
export function normalizeLexiconMethod(lexiconMethod: string): string {
  return lexiconMethod.toLowerCase();
}

export function isChatMethod(lexiconMethod: string): boolean {
  return normalizeLexiconMethod(lexiconMethod).startsWith(CHAT_METHOD_PREFIX);
}

/** Full access or a privileged app password is required for this method. */
export function isPrivilegedMethod(lexiconMethod: string): boolean {
  const normalized = normalizeLexiconMethod(lexiconMethod);
  return normalized.startsWith(CHAT_METHOD_PREFIX) || normalized === CREATE_ACCOUNT_METHOD;
}

export function lexiconMethodIn(methods: ReadonlySet<string>, lexiconMethod: string): boolean {
  const normalized = normalizeLexiconMethod(lexiconMethod);
  for (const method of methods) {
    if (normalizeLexiconMethod(method) === normalized) return true;
  }
  return false;
}
