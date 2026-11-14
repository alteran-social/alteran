const MAX_DOCUMENT_CHARS = 65_536;
const MAX_DEPTH = 64;
const MAX_PROPERTIES = 8192;

type Frame = { readonly kind: 'array' } | { readonly kind: 'object'; readonly keys: Set<string> };

/** Parse a bounded JSON document only when object names are unambiguous. */
export function parseUniqueIdentityJson(text: string): unknown | null {
  if (typeof text !== 'string' || text.length > MAX_DOCUMENT_CHARS) return null;
  const stack: Frame[] = [];
  let properties = 0;
  try {
    for (let index = 0; index < text.length; index++) {
      const character = text[index];
      if (character === '"') {
        const start = index;
        let closed = false;
        while (++index < text.length) {
          if (text[index] === '\\') index++;
          else if (text[index] === '"') { closed = true; break; }
        }
        if (!closed) return null;
        let next = index + 1;
        while (next < text.length && /[\x20\t\r\n]/.test(text[next])) next++;
        if (text[next] === ':') {
          const frame = stack.at(-1);
          const key: unknown = JSON.parse(text.slice(start, index + 1));
          if (!frame || frame.kind !== 'object' || typeof key !== 'string' || key === '__proto__' ||
            frame.keys.has(key) || ++properties > MAX_PROPERTIES) return null;
          frame.keys.add(key);
        }
      } else if (character === '{' || character === '[') {
        if (stack.length >= MAX_DEPTH) return null;
        stack.push(character === '{' ? { kind: 'object', keys: new Set() } : { kind: 'array' });
      } else if (character === '}' || character === ']') {
        const frame = stack.pop();
        if (!frame || frame.kind !== (character === '}' ? 'object' : 'array')) return null;
      }
    }
    if (stack.length) return null;
    return JSON.parse(text);
  } catch {
    return null;
  }
}
