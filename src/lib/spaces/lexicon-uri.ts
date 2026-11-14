const PATH = /^(?:[A-Za-z0-9._~!$&'()*+,;=:@/-]|%[0-9A-Fa-f]{2})*$/;
const QUERY = /^(?:[A-Za-z0-9._~!$&'()*+,;=:@/?-]|%[0-9A-Fa-f]{2})*$/;
const USER_INFO = /^(?:[A-Za-z0-9._~!$&'()*+,;=:-]|%[0-9A-Fa-f]{2})*$/;
const REGISTERED_NAME = /^(?:[A-Za-z0-9._~!$&'()*+,;=-]|%[0-9A-Fa-f]{2})*$/;
const IPV_FUTURE = /^v[0-9A-Fa-f]+\.[A-Za-z0-9._~!$&'()*+,;=:-]+$/i;

/** Validate the generic RFC 3986 URI syntax used by Lexicon. */
export function isLexiconUri(value: unknown): value is string {
  if (typeof value !== "string" || value.length > 8192) return false;
  const parts =
    /^([A-Za-z][A-Za-z0-9+.-]*):([^?#]*)(?:\?([^#]*))?(?:#([^#]*))?$/.exec(
      value,
    );
  if (!parts) return false;
  const hierarchy = parts[2];
  if (
    (parts[3] !== undefined && !QUERY.test(parts[3])) ||
    (parts[4] !== undefined && !QUERY.test(parts[4]))
  ) return false;
  if (!hierarchy.startsWith("//")) return PATH.test(hierarchy);
  const slash = hierarchy.indexOf("/", 2);
  const authority = hierarchy.slice(2, slash === -1 ? undefined : slash);
  const path = slash === -1 ? "" : hierarchy.slice(slash);
  return PATH.test(path) && validAuthority(authority);
}

function validAuthority(authority: string): boolean {
  const at = authority.indexOf("@");
  if (
    at !== -1 &&
    (authority.indexOf("@", at + 1) !== -1 ||
      !USER_INFO.test(authority.slice(0, at)))
  ) {
    return false;
  }
  const hostAndPort = at === -1 ? authority : authority.slice(at + 1);
  if (hostAndPort.startsWith("[")) {
    const end = hostAndPort.indexOf("]");
    if (end === -1) return false;
    const address = hostAndPort.slice(1, end);
    const port = hostAndPort.slice(end + 1);
    if (port && !/^:[0-9]*$/.test(port)) return false;
    if (IPV_FUTURE.test(address)) return true;
    try {
      return new URL(`http://[${address}]/`).hostname.startsWith("[");
    } catch {
      return false;
    }
  }
  const colon = hostAndPort.indexOf(":");
  const name = colon === -1 ? hostAndPort : hostAndPort.slice(0, colon);
  const port = colon === -1 ? "" : hostAndPort.slice(colon + 1);
  return REGISTERED_NAME.test(name) && /^[0-9]*$/.test(port);
}
