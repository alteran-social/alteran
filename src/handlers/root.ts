import type { APIContext } from 'astro';

const HTML_TEMPLATE = (
  handle: string,
  did: string,
) => `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Alteran PDS</title>
    <style>
      :root {
        color-scheme: light dark;
        font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      }
      body {
        margin: 0;
        min-height: 100vh;
        display: flex;
        justify-content: center;
        align-items: center;
        background: radial-gradient(circle at top, #f5f7ff, #e2e8f0);
      }
      .card {
        background: rgba(255, 255, 255, 0.92);
        backdrop-filter: blur(6px);
        padding: 2.5rem;
        border-radius: 1rem;
        box-shadow: 0 25px 45px rgba(15, 23, 42, 0.18);
        text-align: center;
        max-width: 28rem;
      }
      h1 {
        margin: 0 0 1.5rem;
        font-size: clamp(2rem, 4vw, 2.75rem);
        letter-spacing: -0.02em;
        color: #111827;
      }
      p {
        margin: 0.75rem 0;
        color: #334155;
        line-height: 1.55;
      }
      .pill {
        display: inline-block;
        font-family: 'JetBrains Mono', 'Fira Code', monospace;
        font-size: 0.95rem;
        padding: 0.35rem 0.75rem;
        border-radius: 999px;
        background: rgba(59, 130, 246, 0.13);
        color: #1d4ed8;
      }
      a {
        display: inline-flex;
        align-items: center;
        gap: 0.5rem;
        color: #2563eb;
        text-decoration: none;
        font-weight: 600;
        margin-top: 1.5rem;
      }
      a:hover {
        text-decoration: underline;
      }
      svg {
        width: 1.25rem;
        height: 1.25rem;
      }
    </style>
  </head>
  <body>
    <div class="card">
      <h1>Alteran</h1>
      <p>This single-user ATProto Personal Data Server runs on Cloudflare Workers.</p>
      <p>
        <strong>Handle:</strong>
        <span class="pill">${handle}</span>
      </p>
      <p>
        <strong>DID:</strong>
        <span class="pill">${did}</span>
      </p>
      <a href="https://github.com/alteran-social/alteran" target="_blank" rel="noopener noreferrer">
        <svg viewBox="0 0 24 24" role="img" aria-hidden="true" focusable="false">
          <path
            fill="currentColor"
            d="M12 .5a12 12 0 0 0-3.79 23.4c.6.11.82-.26.82-.58v-2.02c-3.34.73-4.04-1.61-4.04-1.61-.55-1.4-1.35-1.77-1.35-1.77-1.1-.75.08-.74.08-.74 1.22.09 1.87 1.26 1.87 1.26 1.08 1.85 2.83 1.32 3.52 1.01.11-.79.42-1.32.76-1.62-2.67-.3-5.47-1.34-5.47-5.98 0-1.32.47-2.39 1.25-3.24-.13-.3-.54-1.52.12-3.17 0 0 1.01-.32 3.3 1.24a11.5 11.5 0 0 1 6 0c2.29-1.56 3.3-1.24 3.3-1.24.66 1.65.25 2.87.12 3.17.78.85 1.25 1.92 1.25 3.24 0 4.66-2.8 5.68-5.48 5.97.43.37.81 1.09.81 2.2v3.26c0 .32.22.7.83.58A12 12 0 0 0 12 .5"
          />
        </svg>
        Source Code
      </a>
    </div>
  </body>
</html>`;

export async function GET({ locals }: APIContext) {
  const { env } = locals.runtime ?? {};
  const handle = String(env?.PDS_HANDLE ?? 'unknown.handle');
  const did = String(env?.PDS_DID ?? 'did:plc:unknown');

  return new Response(HTML_TEMPLATE(handle, did), {
    status: 200,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
    },
  });
}
