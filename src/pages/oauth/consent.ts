import type { APIContext } from 'astro';
import { loadPar } from '../../lib/oauth/store';
import { fetchClientMetadata } from '../../lib/oauth/clients';

export const prerender = false;

function esc(s: string): string { return s.replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;','\'':'&#39;'} as any)[c]); }

export async function GET({ locals, request }: APIContext) {
  const url = new URL(request.url);
  const request_uri = url.searchParams.get('request_uri') || '';
  const client_id = url.searchParams.get('client_id') || '';

  const id = request_uri.replace('urn:ietf:params:oauth:request_uri:', '');
  if (!id) return new Response('invalid request_uri', { status: 400 });
  const par = await loadPar(locals.runtime.env, id);
  if (!par) return new Response('request expired or not found', { status: 400 });
  if (client_id && par.client_id !== client_id) return new Response('client_id mismatch', { status: 400 });

  let meta: any = null;
  try {
    meta = await fetchClientMetadata(par.client_id);
  } catch {
    // Client metadata is decorative on this page; the consent form still renders.
  }
  const clientName = esc(meta?.client_name || new URL(par.client_id).host);
  const logo = typeof meta?.logo_uri === 'string' ? meta.logo_uri : '';
  const scopes = par.scope.split(' ').filter(Boolean);

  const allowUrl = new URL('/oauth/authorize', `${url.protocol}//${url.host}`);
  allowUrl.searchParams.set('request_uri', request_uri);
  allowUrl.searchParams.set('client_id', par.client_id);

  const denyUrl = new URL(par.redirect_uri);
  denyUrl.searchParams.set('state', par.state);
  denyUrl.searchParams.set('error', 'access_denied');

  const html = `<!doctype html>
  <html>
    <head>
      <meta charset="utf-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <title>Authorize ${clientName}</title>
      <style>
        body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; padding: 2rem; color: #222; }
        .card { max-width: 560px; margin: 0 auto; border: 1px solid #ddd; border-radius: 8px; padding: 1.5rem; }
        .client { display: flex; gap: 12px; align-items: center; }
        img.logo { width: 40px; height: 40px; border-radius: 6px; object-fit: cover; }
        ul { padding-left: 1.2rem; }
        .actions { display: flex; gap: 12px; margin-top: 1rem; }
        a.btn { display: inline-block; padding: 8px 14px; border-radius: 6px; text-decoration: none; }
        a.primary { background: #0a66ff; color: #fff; }
        a.secondary { background: #eee; color: #333; }
        .scope { background: #f5f5f7; display: inline-block; padding: 2px 8px; border-radius: 999px; margin-right: 6px; font-size: 12px; }
      </style>
    </head>
    <body>
      <div class="card">
        <div class="client">
          ${logo ? `<img class="logo" src="${esc(logo)}" alt="" />` : ''}
          <div>
            <div style="font-weight:600;">${clientName}</div>
            <div style="color:#555; font-size: 12px;">${esc(par.client_id)}</div>
          </div>
        </div>
        <p style="margin-top:1rem;">This app is requesting:</p>
        <div>
          ${scopes.map((s) => `<span class="scope">${esc(s)}</span>`).join(' ')}
        </div>
        <div class="actions">
          <a class="btn primary" href="${allowUrl.toString()}">Allow</a>
          <a class="btn secondary" href="${denyUrl.toString()}">Deny</a>
        </div>
      </div>
    </body>
  </html>`;

  return new Response(html, { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}

