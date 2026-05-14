#!/usr/bin/env -S deno run -A
/**
 * update-plc.ts
 *
 * Update your PLC document (atproto signing key + PDS endpoint) without re-importing data.
 *
 * Flow:
 * - Auth to NEW PDS (your server) and OLD PDS (previous host, e.g., bsky.social)
 * - NEW: GET com.atproto.identity.getRecommendedDidCredentials (uses your REPO_SIGNING_KEY)
 * - OLD: POST com.atproto.identity.requestPlcOperationSignature (sends email with token)
 * - OLD: POST com.atproto.identity.signPlcOperation with token + recommended payload
 * - NEW: POST com.atproto.identity.submitPlcOperation with returned { operation }
 * - Verify PLC doc and optionally request crawl from relay(s)
 *
 * Usage examples:
 *   deno run -A scripts/update-plc.ts \
 *     --new https://rawkode.dev --old https://bsky.social \
 *     --did did:plc:xxxx --handle rawkode.dev \
 *     --new-pass "$NEW_PWD" --old-pass "$OLD_PWD"
 */

type Args = Record<string, string | boolean>

function parseArgs(argv: string[]): Args {
  const out: Args = {}
  for (let i = 0; i < argv.length; i++) {
    const t = argv[i]
    if (!t.startsWith('--')) continue
    const eq = t.indexOf('=')
    if (eq > 0) {
      out[t.slice(2, eq)] = t.slice(eq + 1)
    } else {
      const k = t.slice(2)
      const nxt = argv[i + 1]
      if (nxt && !nxt.startsWith('--')) { out[k] = nxt; i++ } else { out[k] = true }
    }
  }
  return out
}

async function readLine(): Promise<string> {
  const buf = new Uint8Array(4096)
  const n = await Deno.stdin.read(buf)
  return new TextDecoder().decode(buf.subarray(0, n ?? 0)).trim()
}

async function readLineRaw(): Promise<string> {
  const chunks: number[] = []
  const byte = new Uint8Array(1)
  while (true) {
    const n = await Deno.stdin.read(byte)
    if (n === null) break
    const b = byte[0]
    if (b === 0x03) {
      await Deno.stdout.write(new TextEncoder().encode('\n'))
      Deno.exit(130)
    }
    if (b === 0x0d || b === 0x0a) break
    if (b === 0x7f || b === 0x08) {
      if (chunks.length > 0) chunks.pop()
      continue
    }
    chunks.push(b)
  }
  return new TextDecoder().decode(new Uint8Array(chunks)).trim()
}

async function prompt(label: string, hidden = false): Promise<string> {
  const encoder = new TextEncoder()
  await Deno.stdout.write(encoder.encode(label + ': '))
  if (!hidden) return await readLine()
  try {
    Deno.stdin.setRaw(true)
  } catch {
    return await readLine()
  }
  try {
    return await readLineRaw()
  } finally {
    try { Deno.stdin.setRaw(false) } catch { /* not a TTY */ }
    await Deno.stdout.write(encoder.encode('\n'))
  }
}

async function httpJson(method: string, url: string, opts?: { headers?: Record<string, string>, body?: any }) {
  const res = await fetch(url, {
    method,
    headers: { 'accept': 'application/json', ...(opts?.headers || {}), ...(opts?.body ? { 'content-type': 'application/json' } : {}) },
    body: opts?.body ? JSON.stringify(opts.body) : undefined,
  })
  let json: any = null
  try { json = await res.json() } catch { /* non-JSON response */ }
  return { status: res.status, ok: res.ok, json }
}

async function main() {
  const args = parseArgs(Deno.args)

  const NEW = String(args.new || 'https://rawkode.dev').replace(/\/?$/, '')
  let OLD = typeof args.old === 'string' ? String(args.old).replace(/\/?$/, '') : ''
  const DID = String(args.did || '')
  const HANDLE = String(args.handle || 'rawkode.dev')
  if (!DID || !DID.startsWith('did:plc:')) {
    console.error('ERROR: --did did:plc:... is required')
    Deno.exit(2)
  }

  let NEW_PASS = typeof args['new-pass'] === 'string' ? String(args['new-pass']) : (Deno.env.get('UPDATE_PLC_NEW_PASS') || Deno.env.get('NEW_PASS') || '')
  let OLD_PASS = typeof args['old-pass'] === 'string' ? String(args['old-pass']) : (Deno.env.get('UPDATE_PLC_OLD_PASS') || Deno.env.get('OLD_PASS') || '')
  let TOKEN = typeof args['token'] === 'string' ? String(args['token']) : (Deno.env.get('UPDATE_PLC_TOKEN') || Deno.env.get('PLC_TOKEN') || '')
  const NO_CRAWL = Boolean(args['no-crawl'] || false)
  const RELAYS = String(args.relays || 'bsky.network').split(',').map(s => s.trim()).filter(Boolean)

  console.log(`[INFO] NEW: ${NEW}  OLD: ${OLD}`)
  console.log(`[INFO] DID: ${DID}  HANDLE: ${HANDLE}`)

  if (!NEW_PASS) {
    try {
      NEW_PASS = await prompt(`Password for ${HANDLE} on NEW (${NEW})`, true)
    } catch {
      console.error('No interactive input available. Pass --new-pass or set env NEW_PASS / UPDATE_PLC_NEW_PASS')
      Deno.exit(9)
    }
  }

  if (!OLD) {
    try {
      const plc = await fetch(`https://plc.directory/${encodeURIComponent(DID)}`)
      if (plc.ok) {
        const doc: any = await plc.json()
        OLD = ((): string => {
          const svc = doc?.services?.atproto_pds?.endpoint
          if (typeof svc === 'string') return String(svc)
          const arr = Array.isArray(doc?.service) ? doc.service : []
          const rec = arr.find((s: any) => s?.type === 'AtprotoPersonalDataServer')
          return String(rec?.serviceEndpoint || '')
        })().replace(/\/?$/, '')
      }
    } catch { /* fall through; we'll error below if still empty */ }
  }
  if (!OLD) {
    console.error('ERROR: Could not infer --old from PLC doc; please pass --old https://current.host')
    Deno.exit(2)
  }
  if (!OLD_PASS) {
    try {
      OLD_PASS = await prompt(`Password for ${HANDLE} on OLD (${OLD})`, true)
    } catch {
      console.error('No interactive input available. Pass --old-pass or set env OLD_PASS / UPDATE_PLC_OLD_PASS')
      Deno.exit(10)
    }
  }

  console.log('[INFO] Auth NEW: createSession')
  const createNew = await httpJson('POST', `${NEW}/xrpc/com.atproto.server.createSession`, { body: { identifier: HANDLE, password: NEW_PASS } })
  if (!createNew.ok || !createNew.json?.accessJwt) {
    console.error('[ERROR] NEW createSession failed', createNew.status, createNew.json)
    Deno.exit(3)
  }
  const ACCESS_NEW = createNew.json.accessJwt as string

  console.log('[INFO] Auth OLD: createSession')
  const createOld = await httpJson('POST', `${OLD}/xrpc/com.atproto.server.createSession`, { body: { identifier: HANDLE, password: OLD_PASS } })
  if (!createOld.ok || !createOld.json?.accessJwt) {
    console.error('[ERROR] OLD createSession failed', createOld.status, createOld.json)
    Deno.exit(4)
  }
  const ACCESS_OLD = createOld.json.accessJwt as string

  console.log('[INFO] Fetch NEW recommended credentials')
  const credsRes = await httpJson('GET', `${NEW}/xrpc/com.atproto.identity.getRecommendedDidCredentials`, { headers: { authorization: `Bearer ${ACCESS_NEW}` } })
  if (!credsRes.ok || !credsRes.json?.verificationMethods?.atproto) {
    console.error('[ERROR] getRecommendedDidCredentials failed', credsRes.status, credsRes.json)
    console.error('HINT: Ensure REPO_SIGNING_KEY is set and deployed on NEW')
    Deno.exit(5)
  }
  const CREDS = credsRes.json
  console.log(`[INFO] Recommended atproto: ${CREDS.verificationMethods.atproto}`)

  if (!TOKEN) {
    console.log('[INFO] Requesting PLC token from OLD')
    const tokRes = await httpJson('POST', `${OLD}/xrpc/com.atproto.identity.requestPlcOperationSignature`, { headers: { authorization: `Bearer ${ACCESS_OLD}` } })
    if (!tokRes.ok) {
      console.warn('[WARN] requestPlcOperationSignature did not return 200', tokRes.status)
    }
    try {
      TOKEN = await prompt('Enter PLC token from email', false)
    } catch {
      console.error('No interactive input available. Pass --token or set env PLC_TOKEN / UPDATE_PLC_TOKEN')
      Deno.exit(11)
    }
    if (!TOKEN) {
      console.error('[ERROR] No PLC token provided')
      Deno.exit(6)
    }
  }

  console.log('[INFO] OLD signing PLC operation')
  const signRes = await httpJson('POST', `${OLD}/xrpc/com.atproto.identity.signPlcOperation`, {
    headers: { authorization: `Bearer ${ACCESS_OLD}` },
    body: {
      token: TOKEN,
      rotationKeys: CREDS.rotationKeys,
      alsoKnownAs: CREDS.alsoKnownAs,
      verificationMethods: CREDS.verificationMethods,
      services: CREDS.services,
    },
  })
  const OP = signRes.json?.operation
  if (!signRes.ok || !OP) {
    console.error('[ERROR] signPlcOperation failed', signRes.status, signRes.json)
    Deno.exit(7)
  }

  console.log('[INFO] Submitting PLC operation via NEW')
  const subRes = await httpJson('POST', `${NEW}/xrpc/com.atproto.identity.submitPlcOperation`, {
    headers: { authorization: `Bearer ${ACCESS_NEW}` },
    body: { operation: OP },
  })
  if (!subRes.ok) {
    console.warn('[WARN] NEW submitPlcOperation failed', subRes.status)
    try {
      const mod = await import('@did-plc/lib')
      const client = new (mod as any).Client('https://plc.directory')
      await client.sendOperation(DID, OP)
      console.log('[SUCCESS] PLC operation submitted directly to plc.directory')
    } catch (e: any) {
      console.error('[ERROR] Direct PLC submit failed', e?.message || e)
      console.error('Response from NEW submit:', subRes.json)
      Deno.exit(8)
    }
  } else {
    console.log('[SUCCESS] PLC operation submitted')
  }

  console.log('[INFO] Verifying PLC document...')
  const plc = await fetch(`https://plc.directory/${encodeURIComponent(DID)}`)
  const plcJson: any = await plc.json().catch(() => ({}))
  const keys: string[] = Array.isArray(plcJson.verificationMethod)
    ? plcJson.verificationMethod.map((v: any) => v?.publicKeyMultibase).filter((s: any) => typeof s === 'string')
    : []
  const endpoint = ((): string | null => {
    try {
      const svc = plcJson.services?.atproto_pds?.endpoint
      if (typeof svc === 'string') return svc
      const arr = Array.isArray(plcJson.service) ? plcJson.service : []
      const rec = arr.find((s: any) => s?.type === 'AtprotoPersonalDataServer')
      return typeof rec?.serviceEndpoint === 'string' ? rec.serviceEndpoint : null
    } catch { return null }
  })()
  console.log('[INFO] PLC publicKeyMultibase:', keys.join(', ') || '(none)')
  console.log('[INFO] PLC atproto_pds endpoint:', endpoint || '(none)')

  if (!NO_CRAWL) {
    const host = NEW.replace(/^https?:\/\//i, '')
    for (const r of RELAYS) {
      const url = `https://${r}/xrpc/com.atproto.sync.requestCrawl`
      try {
        const rr = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ hostname: host }) })
        console.log(`[INFO] requestCrawl ${r} -> ${rr.status}`)
      } catch (e: any) {
        console.warn(`[WARN] requestCrawl ${r} error`, e?.message)
      }
    }
  }

  console.log('\nDone. If the PLC doc shows the new key and endpoint, AppView should ingest new commits shortly.')
}

main().catch((e) => { console.error('[FATAL]', e?.stack || String(e)); Deno.exit(1) })
