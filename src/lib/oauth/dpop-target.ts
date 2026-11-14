/** RFC 9449 htu covers the request URI without its query or fragment. */
export function dpopTarget(requestUrl: string): string {
  const url = new URL(requestUrl);
  url.search = "";
  url.hash = "";
  return url.toString();
}
