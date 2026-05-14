export function redirectWellKnownAlias(request: Request): Response | null {
  const url = new URL(request.url);
  if (!url.pathname.startsWith("/well-known/")) {
    return null;
  }

  url.pathname = `/.${url.pathname.slice(1)}`;
  return Response.redirect(url, 308);
}
