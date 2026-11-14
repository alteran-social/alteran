/** Copy own data properties once so accessors cannot change a validated value. */
export function copyPlainRecord(
  value: unknown,
  keys: readonly string[],
): Record<string, unknown> | null {
  try {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      return null;
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) return null;
    const actual = Reflect.ownKeys(value);
    if (
      actual.length !== keys.length ||
      actual.some((key) => typeof key !== "string" || !keys.includes(key))
    ) return null;
    const result: Record<string, unknown> = Object.create(null);
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor?.enumerable || !("value" in descriptor)) return null;
      result[key] = descriptor.value;
    }
    return result;
  } catch {
    return null;
  }
}

/** Preserve bounded extension fields without evaluating their values. */
export function copyPlainRecordWithExtensions(
  value: unknown,
  limit: number,
  keyBudget?: { remaining: number },
): Record<string, unknown> | null {
  try {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      return null;
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) return null;
    const keys = Reflect.ownKeys(value);
    if (keys.length > limit) return null;
    const result: Record<string, unknown> = Object.create(null);
    let totalKeyBytes = 0;
    for (const key of keys) {
      if (typeof key !== "string") return null;
      if (key.length > 8192) return null;
      if (keyBudget) {
        if (
          !Number.isSafeInteger(keyBudget.remaining) ||
          keyBudget.remaining < key.length
        ) return null;
        keyBudget.remaining -= key.length;
      }
      const keyBytes = new TextEncoder().encode(key).byteLength;
      if (keyBudget) {
        const additional = keyBytes - key.length;
        if (additional > keyBudget.remaining) return null;
        keyBudget.remaining -= additional;
      }
      totalKeyBytes += keyBytes;
      if (totalKeyBytes > 65_536) return null;
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor?.enumerable || !("value" in descriptor)) return null;
      result[key] = descriptor.value;
    }
    return result;
  } catch {
    return null;
  }
}

/** Reject holes, custom methods and accessors, then copy each element once. */
export function copyPlainArray(
  value: unknown,
  limit: number,
): unknown[] | null {
  try {
    if (!Array.isArray(value)) return null;
    if (Object.getPrototypeOf(value) !== Array.prototype) return null;
    const length = Object.getOwnPropertyDescriptor(value, "length")?.value;
    if (!Number.isSafeInteger(length) || length < 0 || length > limit) {
      return null;
    }
    if (Reflect.ownKeys(value).length !== length + 1) return null;
    const result: unknown[] = [];
    for (let index = 0; index < length; index++) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor?.enumerable || !("value" in descriptor)) return null;
      result.push(descriptor.value);
    }
    return result;
  } catch {
    return null;
  }
}
